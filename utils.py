import dataclasses
import hashlib
from enum import Enum

SIGNATURE = 0x8f
FILE_VERSION_PADDING_BITS = 4
COMPRESS_ALGORITHM_VERSION_PADDING_BITS = 2
FILE_LENGTH_BYTES_SIZE = 4


class FileVersions(Enum):
    VERSION_SEPT_2022 = 0x0


class CompressAlgorithmVersions(Enum):
    NO_COMPRESS = 0b00


class NoiseCancellationAlgorithmVersions(Enum):
    NO_NOISE_CANCELLATION = 0b00


@dataclasses.dataclass
class Properties:
    signature: int
    file_version: FileVersions
    compress_algorithm_version: CompressAlgorithmVersions
    noise_cancellation_version: NoiseCancellationAlgorithmVersions
    file_size: bytes
    miscellaneous: bytes


def get_checksum(data: bytes):
    result = hashlib.sha1()
    result.update(data)
    return result.digest()[:2]


class ArchiveV0:
    signature_index = 0
    versions_index = 1
    file_size_start_index = 2
    file_size_end_index = 6
    miscellaneous_start_index = 6
    miscellaneous_end_index = 8
    file_contents_start_index = 8

    file_version = FileVersions.VERSION_SEPT_2022
    compress_algorithm_version = CompressAlgorithmVersions.NO_COMPRESS
    noise_cancellation_algorithm = NoiseCancellationAlgorithmVersions.NO_NOISE_CANCELLATION
    file_version_padding_in_bits = 4
    compress_algorithm_padding_in_bits = 2
    file_length_bytes = 4
    algorithms_bitmask = 0b00001111
    noise_cancellation_bitmask = 0b0011

    def encode(self, data: bytes) -> bytes:
        file_size = len(data)
        file_size_bytes = file_size.to_bytes(length=FILE_LENGTH_BYTES_SIZE, byteorder="big")
        result = bytearray(8)
        result[self.signature_index] = SIGNATURE
        result[self.versions_index] = self.file_version.value << FILE_VERSION_PADDING_BITS
        compress_algorithm_with_padding = self.compress_algorithm_version.value << \
                                          self.compress_algorithm_padding_in_bits
        algorithms = compress_algorithm_with_padding | self.noise_cancellation_algorithm.value
        result[self.versions_index] |= algorithms
        result[self.file_size_start_index:self.file_size_end_index] = file_size_bytes
        result[self.miscellaneous_start_index:self.miscellaneous_end_index] = get_checksum(data)
        result.extend(data)
        return bytes(result)
    
    def decode(self, data: bytes) -> bytes:
        algorithms = data[self.versions_index] & self.algorithms_bitmask
        compression_algorithm = CompressAlgorithmVersions(algorithms >> self.compress_algorithm_padding_in_bits)
        if compression_algorithm != CompressAlgorithmVersions.NO_COMPRESS:
            raise Exception(
                f"Compression algorithm should be {CompressAlgorithmVersions.NO_COMPRESS.name} "
                f"({CompressAlgorithmVersions.NO_COMPRESS.value}) but got {compression_algorithm.value}")
        noise_cancellation_algorithm = NoiseCancellationAlgorithmVersions(
            algorithms & self.noise_cancellation_bitmask)
        if noise_cancellation_algorithm != NoiseCancellationAlgorithmVersions.NO_NOISE_CANCELLATION:
            raise Exception(
                f"Noise cancellation algorithm should be {NoiseCancellationAlgorithmVersions.NO_NOISE_CANCELLATION.name} "
                f"({NoiseCancellationAlgorithmVersions.NO_NOISE_CANCELLATION.value})"
                f" but got {noise_cancellation_algorithm.value}")
        file_length_bytes_value = data[self.file_size_start_index:self.file_size_end_index]
        file_length = int.from_bytes(file_length_bytes_value, byteorder="big")
        result = data[self.file_contents_start_index:]
        if len(result) != file_length:
            raise Exception(f"Length mismatch! In header expected {file_length} actual is {len(result)}")
        checksum_expected = data[self.miscellaneous_start_index:self.miscellaneous_end_index]
        checksum_actual = get_checksum(result)
        if checksum_actual != checksum_actual:
            raise Exception(
                f"Checksum mismatch. Expected first two bytes for checksum {checksum_expected} but got {checksum_actual}")
        return result
