#!/usr/bin/env python3

import sys
import shutil
from pathlib import Path

sys.path.append(str(Path(__file__).parent / 'src'))

from main import process_args, generate_key

files_dir = Path('./files')

# Create directory if it doesn't exist
if not files_dir.exists():
    files_dir.mkdir(parents=True)

key_file = files_dir / 'key.bin'
test_files = {
    "chacha20": files_dir / "chacha20.txt",
    "aes-ctr": files_dir / "aes-ctr.txt",
    "aes-cbc": files_dir / "aes-cbc.txt",
}
test_file_content = b"This is a test file to check encryption and decryption."


def cleanup():
    """Clean up previously generated files."""
    if files_dir.exists():
        shutil.rmtree(files_dir)


def encrypt_all_modes(key_file):
    """Encrypt the test file using all modes."""
    print(f"Encrypting with key: {key_file}")
    test_files["chacha20"].write_bytes(test_file_content)
    test_files["aes-ctr"].write_bytes(test_file_content)
    test_files["aes-cbc"].write_bytes(test_file_content)

    sys.argv = ["src/cfich_chacha20.py", "enc", str(test_files["chacha20"]), str(key_file)]
    process_args(method="chacha20")

    sys.argv = ["src/cfich_aes_ctr.py", "enc", str(test_files["aes-ctr"]), str(key_file)]
    process_args(method="aes-ctr")

    sys.argv = ["src/cfich_aes_cbc.py", "enc", str(test_files["aes-cbc"]), str(key_file)]
    process_args(method="aes-cbc")


def decrypt_all_files(key_file):
    """Decrypt all encrypted files."""
    print(f"Decrypting with key: {key_file}")

    sys.argv = ["src/cfich_chacha20.py", "dec", str(files_dir / "chacha20.txt.enc"), str(key_file)]
    process_args(method="chacha20")

    sys.argv = ["src/cfich_aes_ctr.py", "dec", str(files_dir / "aes-ctr.txt.enc"), str(key_file)]
    process_args(method="aes-ctr")

    sys.argv = ["src/cfich_aes_cbc.py", "dec", str(files_dir / "aes-cbc.txt.enc"), str(key_file)]
    process_args(method="aes-cbc")


def verify_decryption():
    """Verify that decryption matches the original by comparing the plain and decrypted files."""
    for method, original_file in test_files.items():
        decrypted_file = files_dir / f"{method}.txt.enc.dec"
        if decrypted_file.read_bytes() == original_file.read_bytes():
            print(f"Decryption successful for: {method}")
        else:
            print(f"Decryption failed for: {method}")


def main():
    cleanup()
    files_dir.mkdir(parents=True, exist_ok=True)
    generate_key(key_file)
    encrypt_all_modes(key_file)
    decrypt_all_files(key_file)
    verify_decryption()


if __name__ == "__main__":
    main()
