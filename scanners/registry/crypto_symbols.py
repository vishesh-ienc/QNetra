"""
QNetra Cryptographic Knowledge Registry — Binary Symbol Database

Maps known cryptographic function symbols (as they appear in ELF/PE symbol tables,
import tables, and export tables) to their cryptographic meaning.

Used by the BinaryScanner's symbol_inspector module to convert raw symbol names
into structured cryptographic findings with high confidence.

Symbol matches have HIGH confidence (0.90-0.95) because confirmed binary symbol
imports are strong evidence of actual cryptographic library usage.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SymbolEntry:
    """A known cryptographic symbol from a binary's symbol table."""
    symbol_name: str         # Exact symbol name as it appears in the binary
    library: str             # Library it belongs to (canonical name)
    algorithm: str           # Canonical algorithm name
    category: str            # ArtifactCategory value
    confidence: float        # Confidence for a confirmed symbol match
    description: str = ""


# ---------------------------------------------------------------------------
# OpenSSL / libcrypto Symbols
# ---------------------------------------------------------------------------

OPENSSL_SYMBOLS: list[SymbolEntry] = [
    # RSA
    SymbolEntry("RSA_generate_key", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.95),
    SymbolEntry("RSA_generate_key_ex", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.95),
    SymbolEntry("RSA_public_encrypt", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.95),
    SymbolEntry("RSA_private_decrypt", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.95),
    SymbolEntry("RSA_public_decrypt", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.93),
    SymbolEntry("RSA_private_encrypt", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.93),
    SymbolEntry("RSA_new", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.88),
    SymbolEntry("RSA_free", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.82),
    SymbolEntry("RSA_sign", "OpenSSL", "RSA", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("RSA_verify", "OpenSSL", "RSA", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("RSA_padding_add_PKCS1_OAEP", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.93),

    # AES
    SymbolEntry("AES_encrypt", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.93),
    SymbolEntry("AES_decrypt", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.93),
    SymbolEntry("AES_set_encrypt_key", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("AES_set_decrypt_key", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("AES_cbc_encrypt", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("AES_cfb128_encrypt", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.93),
    SymbolEntry("EVP_aes_128_gcm", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("EVP_aes_256_gcm", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("EVP_aes_128_cbc", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("EVP_aes_256_cbc", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("EVP_aes_256_ctr", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.95),

    # EVP Generic
    SymbolEntry("EVP_EncryptInit_ex", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.85,
               "Generic encrypt init — algorithm determined by cipher type arg."),
    SymbolEntry("EVP_EncryptUpdate", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.80),
    SymbolEntry("EVP_DecryptInit_ex", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.85),
    SymbolEntry("EVP_DecryptUpdate", "OpenSSL", "AES", "SYMMETRIC_CIPHER", 0.80),
    SymbolEntry("EVP_DigestInit_ex", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.82),
    SymbolEntry("EVP_DigestUpdate", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.78),
    SymbolEntry("EVP_DigestFinal_ex", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.78),
    SymbolEntry("EVP_PKEY_keygen", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.85),
    SymbolEntry("EVP_PKEY_CTX_new", "OpenSSL", "RSA", "ASYMMETRIC_PKC", 0.80),

    # SHA
    SymbolEntry("SHA256", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.93),
    SymbolEntry("SHA256_Init", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.93),
    SymbolEntry("SHA256_Update", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.90),
    SymbolEntry("SHA256_Final", "OpenSSL", "SHA-256", "HASH_FUNCTION", 0.90),
    SymbolEntry("SHA512", "OpenSSL", "SHA-512", "HASH_FUNCTION", 0.93),
    SymbolEntry("SHA512_Init", "OpenSSL", "SHA-512", "HASH_FUNCTION", 0.93),
    SymbolEntry("SHA1", "OpenSSL", "SHA-1", "HASH_FUNCTION", 0.93),
    SymbolEntry("SHA1_Init", "OpenSSL", "SHA-1", "HASH_FUNCTION", 0.93),
    SymbolEntry("MD5", "OpenSSL", "MD5", "HASH_FUNCTION", 0.93),
    SymbolEntry("MD5_Init", "OpenSSL", "MD5", "HASH_FUNCTION", 0.93),

    # EC / ECDSA / ECDH
    SymbolEntry("EC_KEY_generate_key", "OpenSSL", "ECDSA", "ASYMMETRIC_PKC", 0.95),
    SymbolEntry("EC_KEY_new_by_curve_name", "OpenSSL", "ECDSA", "ASYMMETRIC_PKC", 0.93),
    SymbolEntry("EC_KEY_new", "OpenSSL", "ECDSA", "ASYMMETRIC_PKC", 0.85),
    SymbolEntry("ECDSA_sign", "OpenSSL", "ECDSA", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("ECDSA_verify", "OpenSSL", "ECDSA", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("ECDH_compute_key", "OpenSSL", "ECDH", "KEY_EXCHANGE", 0.95),

    # DSA
    SymbolEntry("DSA_generate_key", "OpenSSL", "DSA", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("DSA_sign", "OpenSSL", "DSA", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("DSA_verify", "OpenSSL", "DSA", "DIGITAL_SIGNATURE", 0.95),

    # DH
    SymbolEntry("DH_generate_key", "OpenSSL", "DH", "KEY_EXCHANGE", 0.95),
    SymbolEntry("DH_compute_key", "OpenSSL", "DH", "KEY_EXCHANGE", 0.95),
    SymbolEntry("DH_new", "OpenSSL", "DH", "KEY_EXCHANGE", 0.85),

    # TLS/SSL
    SymbolEntry("SSL_CTX_new", "OpenSSL", "TLS", "PROTOCOL", 0.90),
    SymbolEntry("SSL_new", "OpenSSL", "TLS", "PROTOCOL", 0.85),
    SymbolEntry("SSL_connect", "OpenSSL", "TLS", "PROTOCOL", 0.85),
    SymbolEntry("TLS_client_method", "OpenSSL", "TLS", "PROTOCOL", 0.90),
    SymbolEntry("TLS_server_method", "OpenSSL", "TLS", "PROTOCOL", 0.90),
    SymbolEntry("SSLv23_method", "OpenSSL", "SSL", "PROTOCOL", 0.88),
    SymbolEntry("SSLv3_method", "OpenSSL", "SSL", "PROTOCOL", 0.92,
               "SSLv3 is classically broken."),
]

# ---------------------------------------------------------------------------
# libsodium Symbols
# ---------------------------------------------------------------------------

LIBSODIUM_SYMBOLS: list[SymbolEntry] = [
    SymbolEntry("crypto_box", "libsodium", "ECDH", "KEY_EXCHANGE", 0.93),
    SymbolEntry("crypto_box_keypair", "libsodium", "ECDH", "KEY_EXCHANGE", 0.95),
    SymbolEntry("crypto_sign", "libsodium", "ED25519", "DIGITAL_SIGNATURE", 0.93),
    SymbolEntry("crypto_sign_keypair", "libsodium", "ED25519", "DIGITAL_SIGNATURE", 0.95),
    SymbolEntry("crypto_sign_ed25519_keypair", "libsodium", "ED25519", "DIGITAL_SIGNATURE", 0.97),
    SymbolEntry("crypto_secretbox", "libsodium", "ChaCha20", "SYMMETRIC_CIPHER", 0.90),
    SymbolEntry("crypto_stream_chacha20", "libsodium", "ChaCha20", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("crypto_aead_aes256gcm_encrypt", "libsodium", "AES", "SYMMETRIC_CIPHER", 0.97),
    SymbolEntry("crypto_hash_sha256", "libsodium", "SHA-256", "HASH_FUNCTION", 0.95),
    SymbolEntry("crypto_hash_sha512", "libsodium", "SHA-512", "HASH_FUNCTION", 0.95),
    SymbolEntry("crypto_pwhash_argon2i", "libsodium", "Argon2", "KDF", 0.97),
    SymbolEntry("crypto_pwhash_argon2id", "libsodium", "Argon2", "KDF", 0.97),
    SymbolEntry("crypto_kdf_derive_from_key", "libsodium", "HKDF", "KDF", 0.90),
]

# ---------------------------------------------------------------------------
# mbedTLS Symbols
# ---------------------------------------------------------------------------

MBEDTLS_SYMBOLS: list[SymbolEntry] = [
    SymbolEntry("mbedtls_rsa_init", "mbedTLS", "RSA", "ASYMMETRIC_PKC", 0.93),
    SymbolEntry("mbedtls_rsa_gen_key", "mbedTLS", "RSA", "ASYMMETRIC_PKC", 0.95),
    SymbolEntry("mbedtls_rsa_public", "mbedTLS", "RSA", "ASYMMETRIC_PKC", 0.93),
    SymbolEntry("mbedtls_rsa_private", "mbedTLS", "RSA", "ASYMMETRIC_PKC", 0.93),
    SymbolEntry("mbedtls_aes_init", "mbedTLS", "AES", "SYMMETRIC_CIPHER", 0.93),
    SymbolEntry("mbedtls_aes_setkey_enc", "mbedTLS", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("mbedtls_aes_setkey_dec", "mbedTLS", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("mbedtls_aes_crypt_cbc", "mbedTLS", "AES", "SYMMETRIC_CIPHER", 0.95),
    SymbolEntry("mbedtls_sha256_init", "mbedTLS", "SHA-256", "HASH_FUNCTION", 0.93),
    SymbolEntry("mbedtls_sha256", "mbedTLS", "SHA-256", "HASH_FUNCTION", 0.95),
    SymbolEntry("mbedtls_sha512_init", "mbedTLS", "SHA-512", "HASH_FUNCTION", 0.93),
    SymbolEntry("mbedtls_md5_init", "mbedTLS", "MD5", "HASH_FUNCTION", 0.93),
    SymbolEntry("mbedtls_ecdsa_init", "mbedTLS", "ECDSA", "DIGITAL_SIGNATURE", 0.93),
    SymbolEntry("mbedtls_ecdh_init", "mbedTLS", "ECDH", "KEY_EXCHANGE", 0.93),
    SymbolEntry("mbedtls_ssl_init", "mbedTLS", "TLS", "PROTOCOL", 0.90),
    SymbolEntry("mbedtls_ssl_config_init", "mbedTLS", "TLS", "PROTOCOL", 0.90),
]

# ---------------------------------------------------------------------------
# Windows CNG / BCrypt / WinCrypt Symbols (PE binaries)
# ---------------------------------------------------------------------------

WINDOWS_CRYPTO_SYMBOLS: list[SymbolEntry] = [
    SymbolEntry("BCryptGenerateSymmetricKey", "Windows CNG", "AES", "SYMMETRIC_CIPHER", 0.90),
    SymbolEntry("BCryptEncrypt", "Windows CNG", "AES", "SYMMETRIC_CIPHER", 0.88),
    SymbolEntry("BCryptDecrypt", "Windows CNG", "AES", "SYMMETRIC_CIPHER", 0.88),
    SymbolEntry("BCryptGenRandom", "Windows CNG", "RANDOM", "RANDOM", 0.90),
    SymbolEntry("BCryptCreateHash", "Windows CNG", "SHA-256", "HASH_FUNCTION", 0.88),
    SymbolEntry("BCryptHashData", "Windows CNG", "SHA-256", "HASH_FUNCTION", 0.85),
    SymbolEntry("BCryptOpenAlgorithmProvider", "Windows CNG", "AES", "SYMMETRIC_CIPHER", 0.80),
    SymbolEntry("CryptEncrypt", "Windows CryptoAPI", "RSA", "ASYMMETRIC_PKC", 0.88),
    SymbolEntry("CryptDecrypt", "Windows CryptoAPI", "RSA", "ASYMMETRIC_PKC", 0.88),
    SymbolEntry("CryptGenKey", "Windows CryptoAPI", "RSA", "ASYMMETRIC_PKC", 0.88),
    SymbolEntry("CryptHashData", "Windows CryptoAPI", "SHA-256", "HASH_FUNCTION", 0.85),
    SymbolEntry("CryptAcquireContextA", "Windows CryptoAPI", "RSA", "ASYMMETRIC_PKC", 0.78),
    SymbolEntry("CryptAcquireContextW", "Windows CryptoAPI", "RSA", "ASYMMETRIC_PKC", 0.78),
]

# ---------------------------------------------------------------------------
# All Symbols — unified list and index
# ---------------------------------------------------------------------------

ALL_SYMBOLS: list[SymbolEntry] = (
    OPENSSL_SYMBOLS +
    LIBSODIUM_SYMBOLS +
    MBEDTLS_SYMBOLS +
    WINDOWS_CRYPTO_SYMBOLS
)

_SYMBOL_INDEX: dict[str, SymbolEntry] = {s.symbol_name: s for s in ALL_SYMBOLS}

# Also index common prefix patterns for substring detection in string tables
_SYMBOL_PREFIXES: list[tuple[str, SymbolEntry]] = [
    ("RSA_", next(s for s in OPENSSL_SYMBOLS if s.symbol_name == "RSA_generate_key")),
    ("AES_", next(s for s in OPENSSL_SYMBOLS if s.symbol_name == "AES_encrypt")),
    ("SHA256_", next(s for s in OPENSSL_SYMBOLS if s.symbol_name == "SHA256_Init")),
    ("ECDSA_", next(s for s in OPENSSL_SYMBOLS if s.symbol_name == "ECDSA_sign")),
    ("EVP_", next(s for s in OPENSSL_SYMBOLS if s.symbol_name == "EVP_EncryptInit_ex")),
    ("mbedtls_rsa_", next(s for s in MBEDTLS_SYMBOLS if s.symbol_name == "mbedtls_rsa_init")),
    ("mbedtls_aes_", next(s for s in MBEDTLS_SYMBOLS if s.symbol_name == "mbedtls_aes_init")),
    ("crypto_sign_", next(s for s in LIBSODIUM_SYMBOLS if s.symbol_name == "crypto_sign")),
]


def find_symbol(symbol_name: str) -> SymbolEntry | None:
    """Exact symbol lookup."""
    return _SYMBOL_INDEX.get(symbol_name)


def find_symbol_by_prefix(symbol_name: str) -> SymbolEntry | None:
    """
    Prefix-based lookup for symbols not in the exact index.
    Returns the best-matching prefix entry, or None.
    """
    for prefix, entry in _SYMBOL_PREFIXES:
        if symbol_name.startswith(prefix):
            return entry
    return None
