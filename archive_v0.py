from utils import FileVersions, CompressAlgorithmVersions, NoiseCancellationAlgorithmVersions, SIGNATURE, get_checksum


class ArchiveV0:
    signature = SIGNATURE
    signature_index = 0
    versions_index = 1
    file_size_start_index = 2
    file_size_end_index = 6
    miscellaneous_start_index = 6
    miscellaneous_end_index = 8
    file_contents_start_index = 8

    """
    Header for archive will look like this:
    First byte signature
    Second byte versions (first 4 bits for file version;
    next two bits for compression algorithm version
    last two bits stand for noise cancellation algorithm version)
    Third, fourth, fifth and sixth are for source file length
    Last two bytes store checksum for file's contents (SHA-1)
    """

    file_version = FileVersions.VERSION_SEPT_2022
    compress_algorithm_version = CompressAlgorithmVersions.NO_COMPRESS
    noise_cancellation_algorithm = NoiseCancellationAlgorithmVersions.NO_NOISE_CANCELLATION
    file_version_padding_in_bits = 4
    compress_algorithm_padding_in_bits = 2
    file_size_length_bytes = 4
    algorithms_bitmask = 0b00001111
    noise_cancellation_bitmask = 0b0011

    def __init__(self, input_file: str):
        self.input_file = input_file
        with open(self.input_file, "rb") as descriptor:
            self.data = descriptor.read()

    def encode(self) -> bytes:
        file_size = len(self.data)
        file_size_bytes = file_size.to_bytes(length=self.file_size_length_bytes, byteorder="big")
        result = bytearray(8)
        result[self.signature_index] = self.signature
        result[self.versions_index] = self.file_version.value << self.file_version_padding_in_bits
        compress_algorithm_with_padding = self.compress_algorithm_version.value << \
                                          self.compress_algorithm_padding_in_bits
        algorithms = compress_algorithm_with_padding | self.noise_cancellation_algorithm.value
        result[self.versions_index] |= algorithms
        result[self.file_size_start_index:self.file_size_end_index] = file_size_bytes
        result[self.miscellaneous_start_index:self.miscellaneous_end_index] = get_checksum(self.data)
        result.extend(self.data)
        return bytes(result)

    def decode(self) -> bytes:
        algorithms = self.data[self.versions_index] & self.algorithms_bitmask
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
        file_length_bytes_value = self.data[self.file_size_start_index:self.file_size_end_index]
        file_length = int.from_bytes(file_length_bytes_value, byteorder="big")
        result = self.data[self.file_contents_start_index:]
        if len(result) != file_length:
            raise Exception(f"Length mismatch! In header expected {file_length} actual is {len(result)}")
        checksum_expected = self.data[self.miscellaneous_start_index:self.miscellaneous_end_index]
        checksum_actual = get_checksum(result)
        if checksum_actual != checksum_actual:
            raise Exception(
                f"Checksum mismatch. Expected first two bytes for checksum {checksum_expected} but got {checksum_actual}")
        return result
