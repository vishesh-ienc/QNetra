"""
QNetra Demo — Binary Fixture Generator

Creates a synthetic binary file for the Binary Scanner test fixture.
The file has:
  - Correct ELF magic bytes at offset 0 (so format_detector identifies it as ELF)
  - Embedded printable ASCII strings containing realistic crypto library version
    strings and OpenSSL symbol names (the patterns string_analyzer looks for)

This is a STATIC DATA FILE used to demonstrate string-based binary scanning.
It is NEVER executed. It does not contain real executable code.
"""

import struct
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent.parent / "samples" / "binary_samples" / "sample_crypto_binary.elf"

def build_synthetic_elf():
    """
    Build a minimal synthetic ELF-like binary containing:
      - ELF magic header (16 bytes: \\x7fELF + class/data/version bytes)
      - Filler zero bytes
      - Embedded printable crypto-related strings

    The binary is NOT a valid ELF executable (no PT_LOAD segments, no .text).
    It only carries the 4-byte magic + embedded data strings for scanner demo.
    """

    # ELF magic: \\x7f 'E' 'L' 'F' + class=64bit + data=LE + version=1 + padding
    elf_magic = (
        b"\x7fELF"          # ELF magic
        b"\x02"             # EI_CLASS: 64-bit
        b"\x01"             # EI_DATA: little-endian
        b"\x01"             # EI_VERSION: 1
        b"\x00"             # EI_OSABI: System V
        b"\x00" * 8         # EI_ABIVERSION + padding
    )
    # ELF header continuation (e_type=ET_EXEC, e_machine=x86-64)
    elf_header_cont = struct.pack("<HHIQQQIHHHHHH",
        2,          # e_type: ET_EXEC
        62,         # e_machine: x86-64
        1,          # e_version
        0,          # e_entry
        0,          # e_phoff
        0,          # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )

    # Embedded crypto strings — these match QNetra's string_analyzer patterns
    # Each is separated by null bytes (\\x00) as they would appear in a real binary
    crypto_strings = b"\x00".join([
        b"OpenSSL 3.0.2 15 Mar 2022",
        b"TLS_AES_256_GCM_SHA384",
        b"TLS_CHACHA20_POLY1305_SHA256",
        b"TLS_AES_128_GCM_SHA256",
        b"RSA_public_encrypt",
        b"RSA_private_decrypt",
        b"RSA_generate_key_ex",
        b"EVP_aes_256_gcm",
        b"EVP_aes_128_cbc",
        b"EVP_sha256",
        b"EVP_DigestInit_ex",
        b"EVP_PKEY_keygen",
        b"ECDSA_sign",
        b"ECDSA_verify",
        b"SHA256_Init",
        b"SHA256_Update",
        b"SHA256_Final",
        b"AES_set_encrypt_key",
        b"AES_cbc_encrypt",
        b"libssl.so.3",
        b"libcrypto.so.3",
        b"-----BEGIN CERTIFICATE-----",
        b"secp256r1",
        b"prime256v1",
    ]) + b"\x00"

    # Pad to make it look realistic (512 bytes of ELF header area)
    padding_needed = max(0, 512 - len(elf_magic) - len(elf_header_cont))
    padding = b"\x00" * padding_needed

    binary = elf_magic + elf_header_cont + padding + crypto_strings
    return binary


def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = build_synthetic_elf()
    OUTPUT_PATH.write_bytes(data)
    print(f"[+] Synthetic ELF binary written: {OUTPUT_PATH}")
    print(f"    Size: {len(data)} bytes")
    print(f"    Magic: {data[:4].hex()} (ELF: 7f454c46)")
    print(f"    Contains {len(data.split(b'\\x00'))} embedded string segments")


if __name__ == "__main__":
    main()
