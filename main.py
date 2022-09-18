import os

from archive_v0 import ArchiveV0
from sys import argv

if __name__ == '__main__':
    if len(argv) < 3:
        print("""Provide file to operate and operation type: encode or decode.
Example: python3 main.py encode file.txt""")
        exit(1)
    operation = argv[1]
    file = argv[2]
    if not os.path.exists(file):
        print("No such file exists")
        exit(127)
    if operation not in ("encode", "decode"):
        print(f"No such operation: {operation}")
        exit(1)
    if operation == "encode":
        result = ArchiveV0(file).encode()
        with open(f"{file}.strukovsky_encoded", "wb") as descriptor:
            descriptor.write(result)
    elif operation == "decode":
        result = ArchiveV0(file).decode()
        with open(f"{file}.strukovsky_decoded", "wb") as descriptor:
            descriptor.write(result)
