"""
QNetra Cryptographic Knowledge Registry — API-to-Algorithm Mapping

Maps known cryptographic API calls (function names, class constructors) to:
  - The algorithm they implement
  - The artifact category
  - Argument extraction rules
  - Base confidence for an API call detection

This registry is used by the RepositoryScanner's language analyzers to convert
AST-detected function calls into structured cryptographic findings.

Design principle: Entries are LIBRARY-SCOPED to avoid false positives.
A generic function named "encrypt" does not generate a finding.
Only known library-qualified APIs trigger findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ArgExtractionRule:
    """Describes how to extract algorithm configuration from API call arguments."""
    key_size_arg: Optional[str | int] = None  # arg name or positional index for key size
    mode_arg: Optional[str | int] = None      # arg name or index for cipher mode
    curve_arg: Optional[str | int] = None     # arg name or index for EC curve
    algorithm_arg: Optional[str | int] = None # arg name or index where algorithm name is passed


@dataclass(frozen=True)
class APIEntry:
    """A single API function/method call known to perform cryptographic operations."""
    library: str                  # Library canonical name (from crypto_libraries.py)
    api_name: str                 # Function/method/class name as it appears in source
    algorithm: str                # Canonical algorithm name (from crypto_algorithms.py)
    category: str                 # ArtifactCategory enum value string
    base_confidence: float        # Confidence for detecting this exact API call
    arg_rules: ArgExtractionRule = field(default_factory=ArgExtractionRule)
    notes: str = ""


# ---------------------------------------------------------------------------
# Python API Registry
# ---------------------------------------------------------------------------

PYTHON_API_MAP: list[APIEntry] = [

    # --- PyCryptodome / PyCrypto ---
    APIEntry("pycryptodome", "RSA.generate", "RSA", "ASYMMETRIC_PKC", 0.95,
             ArgExtractionRule(key_size_arg=0),
             "Generates RSA keypair. First arg is key size (bits)."),
    APIEntry("pycryptodome", "RSA.import_key", "RSA", "ASYMMETRIC_PKC", 0.92),
    APIEntry("pycryptodome", "RSA.construct", "RSA", "ASYMMETRIC_PKC", 0.90),
    APIEntry("pycryptodome", "PKCS1_OAEP.new", "RSA", "ASYMMETRIC_PKC", 0.93,
             notes="RSA OAEP encryption/decryption."),
    APIEntry("pycryptodome", "AES.new", "AES", "SYMMETRIC_CIPHER", 0.95,
             ArgExtractionRule(mode_arg=1),
             "Second arg is cipher mode constant (e.g. AES.MODE_GCM)."),
    APIEntry("pycryptodome", "DES.new", "DES", "SYMMETRIC_CIPHER", 0.95),
    APIEntry("pycryptodome", "DES3.new", "3DES", "SYMMETRIC_CIPHER", 0.95),
    APIEntry("pycryptodome", "SHA256.new", "SHA-256", "HASH_FUNCTION", 0.95),
    APIEntry("pycryptodome", "SHA512.new", "SHA-512", "HASH_FUNCTION", 0.95),
    APIEntry("pycryptodome", "SHA1.new", "SHA-1", "HASH_FUNCTION", 0.95),
    APIEntry("pycryptodome", "MD5.new", "MD5", "HASH_FUNCTION", 0.95),
    APIEntry("pycryptodome", "HMAC.new", "HMAC", "MAC", 0.93),
    APIEntry("pycryptodome", "ECC.generate", "ECDSA", "ASYMMETRIC_PKC", 0.93,
             ArgExtractionRule(curve_arg="curve")),
    APIEntry("pycryptodome", "DSA.generate", "DSA", "DIGITAL_SIGNATURE", 0.93,
             ArgExtractionRule(key_size_arg=0)),

    # --- cryptography (PyCA) ---
    APIEntry("cryptography", "rsa.generate_private_key", "RSA", "ASYMMETRIC_PKC", 0.96,
             ArgExtractionRule(key_size_arg="key_size"),
             "Standard PyCA RSA key generation."),
    APIEntry("cryptography", "rsa.RSAPublicKey", "RSA", "ASYMMETRIC_PKC", 0.88),
    APIEntry("cryptography", "ec.generate_private_key", "ECDSA", "ASYMMETRIC_PKC", 0.95,
             ArgExtractionRule(curve_arg=0)),
    APIEntry("cryptography", "ec.ECDH", "ECDH", "KEY_EXCHANGE", 0.93),
    APIEntry("cryptography", "dh.generate_parameters", "DH", "KEY_EXCHANGE", 0.95,
             ArgExtractionRule(key_size_arg="key_size")),
    APIEntry("cryptography", "Cipher", "AES", "SYMMETRIC_CIPHER", 0.88,
             notes="Algorithm and mode passed as constructor args."),
    APIEntry("cryptography", "algorithms.AES", "AES", "SYMMETRIC_CIPHER", 0.96,
             ArgExtractionRule(key_size_arg=0),
             "Key length extractable from key argument length."),
    APIEntry("cryptography", "algorithms.TripleDES", "3DES", "SYMMETRIC_CIPHER", 0.96),
    APIEntry("cryptography", "modes.GCM", "AES", "SYMMETRIC_CIPHER", 0.88,
             notes="Mode indicator — typically accompanies algorithms.AES."),
    APIEntry("cryptography", "modes.CBC", "AES", "SYMMETRIC_CIPHER", 0.85),
    APIEntry("cryptography", "hashes.SHA256", "SHA-256", "HASH_FUNCTION", 0.96),
    APIEntry("cryptography", "hashes.SHA512", "SHA-512", "HASH_FUNCTION", 0.96),
    APIEntry("cryptography", "hashes.SHA1", "SHA-1", "HASH_FUNCTION", 0.96),
    APIEntry("cryptography", "hashes.MD5", "MD5", "HASH_FUNCTION", 0.96),
    APIEntry("cryptography", "hashes.SHA384", "SHA-384", "HASH_FUNCTION", 0.96),
    APIEntry("cryptography", "hmac.HMAC", "HMAC", "MAC", 0.95),
    APIEntry("cryptography", "PBKDF2HMAC", "PBKDF2", "KDF", 0.95),
    APIEntry("cryptography", "HKDF", "HKDF", "KDF", 0.95),
    APIEntry("cryptography", "Scrypt", "scrypt", "KDF", 0.95),
    APIEntry("cryptography", "x509.load_pem_x509_certificate", "RSA", "CERTIFICATE", 0.85),

    # --- hashlib (stdlib) ---
    APIEntry("hashlib", "hashlib.md5", "MD5", "HASH_FUNCTION", 0.93),
    APIEntry("hashlib", "hashlib.sha1", "SHA-1", "HASH_FUNCTION", 0.93),
    APIEntry("hashlib", "hashlib.sha256", "SHA-256", "HASH_FUNCTION", 0.93),
    APIEntry("hashlib", "hashlib.sha384", "SHA-384", "HASH_FUNCTION", 0.93),
    APIEntry("hashlib", "hashlib.sha512", "SHA-512", "HASH_FUNCTION", 0.93),
    APIEntry("hashlib", "hashlib.sha3_256", "SHA-3", "HASH_FUNCTION", 0.93),
    APIEntry("hashlib", "hashlib.new", "UNKNOWN", "HASH_FUNCTION", 0.75,
             ArgExtractionRule(algorithm_arg=0),
             "Algorithm name passed as first string arg — extractable if literal."),
    APIEntry("hashlib", "hashlib.pbkdf2_hmac", "PBKDF2", "KDF", 0.93,
             ArgExtractionRule(algorithm_arg=0)),

    # --- hmac (stdlib) ---
    APIEntry("hmac", "hmac.new", "HMAC", "MAC", 0.92,
             ArgExtractionRule(algorithm_arg="digestmod")),
    APIEntry("hmac", "hmac.HMAC", "HMAC", "MAC", 0.92),

    # --- ssl (stdlib) ---
    APIEntry("ssl", "ssl.SSLContext", "TLS", "PROTOCOL", 0.85),
    APIEntry("ssl", "ssl.wrap_socket", "TLS", "PROTOCOL", 0.85),

    # --- bcrypt ---
    APIEntry("bcrypt", "bcrypt.hashpw", "bcrypt", "KDF", 0.95),
    APIEntry("bcrypt", "bcrypt.checkpw", "bcrypt", "KDF", 0.90),
    APIEntry("bcrypt", "bcrypt.gensalt", "bcrypt", "KDF", 0.88),
]


# ---------------------------------------------------------------------------
# JavaScript / Node.js API Registry
# ---------------------------------------------------------------------------

JAVASCRIPT_API_MAP: list[APIEntry] = [
    APIEntry("node:crypto", "crypto.createCipheriv", "AES", "SYMMETRIC_CIPHER", 0.90,
             ArgExtractionRule(algorithm_arg=0),
             "First arg is algorithm string e.g. 'aes-256-gcm'."),
    APIEntry("node:crypto", "crypto.createDecipheriv", "AES", "SYMMETRIC_CIPHER", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("node:crypto", "crypto.createHash", "SHA-256", "HASH_FUNCTION", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("node:crypto", "crypto.createHmac", "HMAC", "MAC", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("node:crypto", "crypto.generateKeyPair", "RSA", "ASYMMETRIC_PKC", 0.90,
             ArgExtractionRule(algorithm_arg=0, key_size_arg="modulusLength")),
    APIEntry("node:crypto", "crypto.createSign", "RSA", "DIGITAL_SIGNATURE", 0.88,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("node:crypto", "crypto.createVerify", "RSA", "DIGITAL_SIGNATURE", 0.85,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("node:crypto", "crypto.pbkdf2", "PBKDF2", "KDF", 0.92,
             ArgExtractionRule(algorithm_arg=4)),
    APIEntry("node:crypto", "crypto.pbkdf2Sync", "PBKDF2", "KDF", 0.92),
    APIEntry("node:crypto", "crypto.scrypt", "scrypt", "KDF", 0.92),
    APIEntry("node:crypto", "crypto.scryptSync", "scrypt", "KDF", 0.92),

    # jsonwebtoken
    APIEntry("jsonwebtoken", "jwt.sign", "RSA", "DIGITAL_SIGNATURE", 0.85,
             ArgExtractionRule(algorithm_arg="algorithm"),
             "Algorithm in options.algorithm (HS256, RS256, ES256...)."),
    APIEntry("jsonwebtoken", "jwt.verify", "RSA", "DIGITAL_SIGNATURE", 0.82),

    # crypto-js
    APIEntry("crypto-js", "CryptoJS.AES.encrypt", "AES", "SYMMETRIC_CIPHER", 0.92),
    APIEntry("crypto-js", "CryptoJS.AES.decrypt", "AES", "SYMMETRIC_CIPHER", 0.92),
    APIEntry("crypto-js", "CryptoJS.SHA256", "SHA-256", "HASH_FUNCTION", 0.92),
    APIEntry("crypto-js", "CryptoJS.SHA512", "SHA-512", "HASH_FUNCTION", 0.92),
    APIEntry("crypto-js", "CryptoJS.MD5", "MD5", "HASH_FUNCTION", 0.92),
    APIEntry("crypto-js", "CryptoJS.HmacSHA256", "HMAC", "MAC", 0.92),
]


# ---------------------------------------------------------------------------
# Java API Registry
# ---------------------------------------------------------------------------

JAVA_API_MAP: list[APIEntry] = [
    APIEntry("javax.crypto", "KeyGenerator.getInstance", "AES", "SYMMETRIC_CIPHER", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("javax.crypto", "Cipher.getInstance", "AES", "SYMMETRIC_CIPHER", 0.90,
             ArgExtractionRule(algorithm_arg=0),
             "Transformation string e.g. 'AES/GCM/NoPadding'."),
    APIEntry("javax.crypto", "SecretKeyFactory.getInstance", "PBKDF2", "KDF", 0.88,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("java.security", "KeyPairGenerator.getInstance", "RSA", "ASYMMETRIC_PKC", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("java.security", "MessageDigest.getInstance", "SHA-256", "HASH_FUNCTION", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("java.security", "Signature.getInstance", "RSA", "DIGITAL_SIGNATURE", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
    APIEntry("java.security", "Mac.getInstance", "HMAC", "MAC", 0.90,
             ArgExtractionRule(algorithm_arg=0)),
]


# ---------------------------------------------------------------------------
# C/C++ API Registry (OpenSSL EVP / high-level APIs)
# ---------------------------------------------------------------------------

CPP_API_MAP: list[APIEntry] = [
    APIEntry("OpenSSL", "EVP_EncryptInit_ex", "AES", "SYMMETRIC_CIPHER", 0.90,
             notes="Cipher type passed as second arg (EVP_aes_256_gcm() etc.)."),
    APIEntry("OpenSSL", "EVP_DecryptInit_ex", "AES", "SYMMETRIC_CIPHER", 0.90),
    APIEntry("OpenSSL", "EVP_DigestInit_ex", "SHA-256", "HASH_FUNCTION", 0.88),
    APIEntry("OpenSSL", "EVP_MD_CTX_new", "SHA-256", "HASH_FUNCTION", 0.80),
    APIEntry("OpenSSL", "RSA_generate_key_ex", "RSA", "ASYMMETRIC_PKC", 0.95,
             ArgExtractionRule(key_size_arg=1)),
    APIEntry("OpenSSL", "RSA_public_encrypt", "RSA", "ASYMMETRIC_PKC", 0.93),
    APIEntry("OpenSSL", "RSA_private_decrypt", "RSA", "ASYMMETRIC_PKC", 0.93),
    APIEntry("OpenSSL", "AES_encrypt", "AES", "SYMMETRIC_CIPHER", 0.90),
    APIEntry("OpenSSL", "AES_set_encrypt_key", "AES", "SYMMETRIC_CIPHER", 0.92,
             ArgExtractionRule(key_size_arg=1)),
    APIEntry("OpenSSL", "SHA256", "SHA-256", "HASH_FUNCTION", 0.90),
    APIEntry("OpenSSL", "SHA512", "SHA-512", "HASH_FUNCTION", 0.90),
    APIEntry("OpenSSL", "SHA1", "SHA-1", "HASH_FUNCTION", 0.90),
    APIEntry("OpenSSL", "MD5", "MD5", "HASH_FUNCTION", 0.90),
    APIEntry("OpenSSL", "EC_KEY_generate_key", "ECDSA", "ASYMMETRIC_PKC", 0.93),
    APIEntry("OpenSSL", "EC_KEY_new_by_curve_name", "ECDSA", "ASYMMETRIC_PKC", 0.90,
             ArgExtractionRule(curve_arg=0)),
    APIEntry("OpenSSL", "ECDH_compute_key", "ECDH", "KEY_EXCHANGE", 0.93),
    APIEntry("OpenSSL", "SSL_CTX_new", "TLS", "PROTOCOL", 0.88),
    APIEntry("OpenSSL", "SSL_connect", "TLS", "PROTOCOL", 0.82),
]


# ---------------------------------------------------------------------------
# Unified lookup helpers
# ---------------------------------------------------------------------------

_ALL_API_MAPS: dict[str, list[APIEntry]] = {
    "python": PYTHON_API_MAP,
    "javascript": JAVASCRIPT_API_MAP,
    "java": JAVA_API_MAP,
    "cpp": CPP_API_MAP,
}

# Build reverse index: (language, api_name) -> APIEntry
_API_INDEX: dict[tuple[str, str], APIEntry] = {}
for lang, entries in _ALL_API_MAPS.items():
    for entry in entries:
        # Index by full dotted name and short name
        _API_INDEX[(lang, entry.api_name.lower())] = entry
        short = entry.api_name.split(".")[-1].lower()
        _API_INDEX.setdefault((lang, short), entry)


def find_api_entry(language: str, call_name: str) -> APIEntry | None:
    """
    Look up an API call in the registry.

    Args:
        language: 'python', 'javascript', 'java', 'cpp'
        call_name: Function/method name as seen in source (may be dotted or short).

    Returns:
        APIEntry if found, None otherwise.
    """
    lang = language.lower()
    name = call_name.strip()
    # Try exact match first
    result = _API_INDEX.get((lang, name.lower()))
    if result:
        return result
    # Try without library qualifier (short name)
    short = name.split(".")[-1].lower()
    return _API_INDEX.get((lang, short))


def get_api_map_for_language(language: str) -> list[APIEntry]:
    return _ALL_API_MAPS.get(language.lower(), [])
