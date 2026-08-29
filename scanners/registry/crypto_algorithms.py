"""
QNetra Cryptographic Knowledge Registry — Algorithm Definitions

Defines the canonical registry of cryptographic algorithms recognized by QNetra.
Each entry maps an algorithm identifier to its canonical name, aliases,
functional category, and quantum vulnerability classification.

This registry is the authoritative source for algorithm identification across all scanners.
It is intentionally NOT exhaustive — it covers algorithms commonly encountered in
enterprise codebases with high detection value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class QuantumThreat(str, Enum):
    """Classification of an algorithm's quantum vulnerability."""
    SHOR_POLYNOMIAL_BREAK = "SHOR_POLYNOMIAL_BREAK"  # Asymmetric PKC: fully broken
    GROVER_BIT_HALVING = "GROVER_BIT_HALVING"         # Symmetric: security halved
    CLASSICALLY_BROKEN = "CLASSICALLY_BROKEN"          # Already weak (MD5, SHA-1, DES)
    QUANTUM_RESISTANT = "QUANTUM_RESISTANT"            # AES-256, SHA-3, NIST PQC


class CryptoCategory(str, Enum):
    ASYMMETRIC_PKC = "ASYMMETRIC_PKC"
    SYMMETRIC_CIPHER = "SYMMETRIC_CIPHER"
    HASH_FUNCTION = "HASH_FUNCTION"
    KDF = "KDF"
    MAC = "MAC"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    PROTOCOL = "PROTOCOL"
    RANDOM = "RANDOM"
    HYBRID = "HYBRID"


@dataclass(frozen=True)
class AlgorithmEntry:
    """A single entry in the algorithm registry."""
    canonical_name: str            # The normalized name used throughout QNetra
    aliases: tuple[str, ...]       # Known alternative names/spellings (lowercase for matching)
    category: CryptoCategory
    quantum_threat: QuantumThreat
    min_secure_key_bits: int = 0   # Classical minimum; 0 means N/A (hash functions, etc.)
    notes: str = ""


# ---------------------------------------------------------------------------
# Algorithm Registry
# ---------------------------------------------------------------------------

ALGORITHM_REGISTRY: dict[str, AlgorithmEntry] = {

    # -----------------------------------------------------------------------
    # Asymmetric / Public Key Cryptography — Shor-vulnerable
    # -----------------------------------------------------------------------
    "RSA": AlgorithmEntry(
        canonical_name="RSA",
        aliases=("rsa", "rsa_oaep", "rsa-oaep", "rsa-pss", "rsassa", "pkcs1",
                 "rsa_pkcs1", "rsa1_5"),
        category=CryptoCategory.ASYMMETRIC_PKC,
        quantum_threat=QuantumThreat.SHOR_POLYNOMIAL_BREAK,
        min_secure_key_bits=2048,
        notes="Completely broken by Shor's algorithm regardless of key size.",
    ),
    "DSA": AlgorithmEntry(
        canonical_name="DSA",
        aliases=("dsa",),
        category=CryptoCategory.DIGITAL_SIGNATURE,
        quantum_threat=QuantumThreat.SHOR_POLYNOMIAL_BREAK,
        min_secure_key_bits=2048,
        notes="Discrete logarithm problem — fully broken by Shor's algorithm.",
    ),
    "DH": AlgorithmEntry(
        canonical_name="DH",
        aliases=("dh", "diffie-hellman", "diffie_hellman", "dhparam", "dh_param"),
        category=CryptoCategory.KEY_EXCHANGE,
        quantum_threat=QuantumThreat.SHOR_POLYNOMIAL_BREAK,
        min_secure_key_bits=2048,
        notes="Finite field DH — fully broken by Shor's algorithm.",
    ),
    "ECDH": AlgorithmEntry(
        canonical_name="ECDH",
        aliases=("ecdh", "ecdhe", "x25519", "x448", "elliptic_curve_diffie_hellman"),
        category=CryptoCategory.KEY_EXCHANGE,
        quantum_threat=QuantumThreat.SHOR_POLYNOMIAL_BREAK,
        min_secure_key_bits=256,
        notes="Elliptic curve DH — broken by Shor's algorithm on elliptic curves.",
    ),
    "ECDSA": AlgorithmEntry(
        canonical_name="ECDSA",
        aliases=("ecdsa", "ec", "ecc", "elliptic_curve", "elliptic curve"),
        category=CryptoCategory.DIGITAL_SIGNATURE,
        quantum_threat=QuantumThreat.SHOR_POLYNOMIAL_BREAK,
        min_secure_key_bits=256,
        notes="Elliptic curve DSA — broken by Shor's algorithm.",
    ),
    "ED25519": AlgorithmEntry(
        canonical_name="Ed25519",
        aliases=("ed25519", "edwards25519", "eddsa"),
        category=CryptoCategory.DIGITAL_SIGNATURE,
        quantum_threat=QuantumThreat.SHOR_POLYNOMIAL_BREAK,
        notes="EdDSA over Curve25519 — broken by Shor's algorithm.",
    ),

    # -----------------------------------------------------------------------
    # Symmetric Ciphers — Grover-impacted
    # -----------------------------------------------------------------------
    "AES": AlgorithmEntry(
        canonical_name="AES",
        aliases=("aes", "aes128", "aes-128", "aes_128", "aes192", "aes-192",
                 "aes_192", "aes256", "aes-256", "aes_256", "rijndael",
                 "aes-128-cbc", "aes-256-cbc", "aes-128-gcm", "aes-256-gcm",
                 "aes-128-ctr", "aes-256-ctr", "aes-128-cfb", "aes-256-cfb",
                 "aes-128-ecb", "aes-256-ecb"),
        category=CryptoCategory.SYMMETRIC_CIPHER,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        min_secure_key_bits=256,
        notes="AES-128 provides ~64-bit quantum security; AES-256 provides ~128-bit.",
    ),
    "DES": AlgorithmEntry(
        canonical_name="DES",
        aliases=("des",),
        category=CryptoCategory.SYMMETRIC_CIPHER,
        quantum_threat=QuantumThreat.CLASSICALLY_BROKEN,
        min_secure_key_bits=999,  # No secure key size exists
        notes="Classically broken — 56-bit key, fully deprecated.",
    ),
    "3DES": AlgorithmEntry(
        canonical_name="3DES",
        aliases=("3des", "triple-des", "triple_des", "tripledes", "des3", "des-ede",
                 "des-ede3", "desede", "tdea"),
        category=CryptoCategory.SYMMETRIC_CIPHER,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        min_secure_key_bits=999,  # Effective 112-bit, deprecated by NIST SP 800-131A
        notes="Deprecated by NIST. Effective 112-bit security — insufficient.",
    ),
    "CHACHA20": AlgorithmEntry(
        canonical_name="ChaCha20",
        aliases=("chacha20", "chacha", "chacha20-poly1305", "xchacha20"),
        category=CryptoCategory.SYMMETRIC_CIPHER,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        min_secure_key_bits=256,
        notes="256-bit key provides ~128-bit quantum security — acceptable.",
    ),
    "RC4": AlgorithmEntry(
        canonical_name="RC4",
        aliases=("rc4", "arcfour", "arc4"),
        category=CryptoCategory.SYMMETRIC_CIPHER,
        quantum_threat=QuantumThreat.CLASSICALLY_BROKEN,
        notes="Classically broken stream cipher — forbidden by RFC 7465.",
    ),

    # -----------------------------------------------------------------------
    # Hash Functions
    # -----------------------------------------------------------------------
    "MD5": AlgorithmEntry(
        canonical_name="MD5",
        aliases=("md5",),
        category=CryptoCategory.HASH_FUNCTION,
        quantum_threat=QuantumThreat.CLASSICALLY_BROKEN,
        notes="Classically broken — collision attacks feasible on commodity hardware.",
    ),
    "SHA-1": AlgorithmEntry(
        canonical_name="SHA-1",
        aliases=("sha1", "sha-1", "sha_1"),
        category=CryptoCategory.HASH_FUNCTION,
        quantum_threat=QuantumThreat.CLASSICALLY_BROKEN,
        notes="Classically broken — SHAttered collision (2017). NIST deprecated.",
    ),
    "SHA-256": AlgorithmEntry(
        canonical_name="SHA-256",
        aliases=("sha256", "sha-256", "sha_256", "sha2", "sha2-256"),
        category=CryptoCategory.HASH_FUNCTION,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        notes="BHT algorithm reduces to ~85-bit quantum collision resistance.",
    ),
    "SHA-384": AlgorithmEntry(
        canonical_name="SHA-384",
        aliases=("sha384", "sha-384", "sha_384", "sha2-384"),
        category=CryptoCategory.HASH_FUNCTION,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="Sufficient post-quantum security (~192-bit quantum collision resistance).",
    ),
    "SHA-512": AlgorithmEntry(
        canonical_name="SHA-512",
        aliases=("sha512", "sha-512", "sha_512", "sha2-512"),
        category=CryptoCategory.HASH_FUNCTION,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="Strong post-quantum hash (~256-bit quantum collision resistance).",
    ),
    "SHA-3": AlgorithmEntry(
        canonical_name="SHA-3",
        aliases=("sha3", "sha-3", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
                 "shake128", "shake256", "keccak"),
        category=CryptoCategory.HASH_FUNCTION,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="SHA-3/SHAKE family — quantum resistant at 256+ bit variants.",
    ),

    # -----------------------------------------------------------------------
    # Key Derivation Functions
    # -----------------------------------------------------------------------
    "PBKDF2": AlgorithmEntry(
        canonical_name="PBKDF2",
        aliases=("pbkdf2", "pbkdf2_hmac", "pbkdf2-hmac"),
        category=CryptoCategory.KDF,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        notes="Security depends on underlying hash — use with SHA-256+ and sufficient iterations.",
    ),
    "BCRYPT": AlgorithmEntry(
        canonical_name="bcrypt",
        aliases=("bcrypt",),
        category=CryptoCategory.KDF,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        notes="Memory-hard KDF — Grover provides quadratic speedup.",
    ),
    "ARGON2": AlgorithmEntry(
        canonical_name="Argon2",
        aliases=("argon2", "argon2id", "argon2i", "argon2d"),
        category=CryptoCategory.KDF,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="Memory-hard, winner of Password Hashing Competition 2015.",
    ),
    "HKDF": AlgorithmEntry(
        canonical_name="HKDF",
        aliases=("hkdf",),
        category=CryptoCategory.KDF,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        notes="HMAC-based KDF — security depends on underlying hash.",
    ),
    "SCRYPT": AlgorithmEntry(
        canonical_name="scrypt",
        aliases=("scrypt",),
        category=CryptoCategory.KDF,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
    ),

    # -----------------------------------------------------------------------
    # MAC / HMAC
    # -----------------------------------------------------------------------
    "HMAC": AlgorithmEntry(
        canonical_name="HMAC",
        aliases=("hmac", "hmac-sha256", "hmac-sha1", "hmac-md5", "hmac_sha256",
                 "hmacsha256", "hmacsha1"),
        category=CryptoCategory.MAC,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        notes="Security depends on underlying hash algorithm.",
    ),

    # -----------------------------------------------------------------------
    # Protocols — detect dangerous TLS/SSL versions
    # -----------------------------------------------------------------------
    "SSL": AlgorithmEntry(
        canonical_name="SSL",
        aliases=("sslv2", "sslv3", "ssl2", "ssl3", "ssl_v2", "ssl_v3", "sslv2_client",
                 "ssl_protocol"),
        category=CryptoCategory.PROTOCOL,
        quantum_threat=QuantumThreat.CLASSICALLY_BROKEN,
        notes="All SSL versions are classically broken — formally prohibited.",
    ),
    "TLS": AlgorithmEntry(
        canonical_name="TLS",
        aliases=("tls", "tls1", "tls1.0", "tls1.1", "tls1.2", "tls1.3",
                 "tls_v1", "tls_v1_1", "tls_v1_2", "tlsv1", "tlsv1_2",
                 "tlsv1_client_method", "tlsv1_2_client_method"),
        category=CryptoCategory.PROTOCOL,
        quantum_threat=QuantumThreat.GROVER_BIT_HALVING,
        notes="TLS 1.0/1.1 deprecated. TLS 1.2 acceptable. TLS 1.3 recommended.",
    ),

    # -----------------------------------------------------------------------
    # NIST-Approved Post-Quantum Algorithms (for detection of compliant usage)
    # -----------------------------------------------------------------------
    "ML-KEM": AlgorithmEntry(
        canonical_name="ML-KEM",
        aliases=("ml-kem", "mlkem", "kyber", "crystals-kyber", "ml_kem"),
        category=CryptoCategory.KEY_EXCHANGE,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="NIST FIPS 203. Module-Lattice-Based Key Encapsulation Mechanism.",
    ),
    "ML-DSA": AlgorithmEntry(
        canonical_name="ML-DSA",
        aliases=("ml-dsa", "mldsa", "dilithium", "crystals-dilithium", "ml_dsa"),
        category=CryptoCategory.DIGITAL_SIGNATURE,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="NIST FIPS 204. Module-Lattice-Based Digital Signature Algorithm.",
    ),
    "SLH-DSA": AlgorithmEntry(
        canonical_name="SLH-DSA",
        aliases=("slh-dsa", "slhdsa", "sphincs", "sphincs+", "slh_dsa"),
        category=CryptoCategory.DIGITAL_SIGNATURE,
        quantum_threat=QuantumThreat.QUANTUM_RESISTANT,
        notes="NIST FIPS 205. Stateless Hash-Based Digital Signature.",
    ),
}


# Build reverse lookup: alias -> canonical_name
_ALIAS_TO_CANONICAL: dict[str, str] = {}
for _canonical, _entry in ALGORITHM_REGISTRY.items():
    for _alias in _entry.aliases:
        _ALIAS_TO_CANONICAL[_alias.lower()] = _canonical
    _ALIAS_TO_CANONICAL[_canonical.lower()] = _canonical


def resolve_algorithm(raw_name: str) -> tuple[str, AlgorithmEntry] | tuple[None, None]:
    """
    Resolve a raw algorithm name string to its canonical entry.

    Args:
        raw_name: Any algorithm name/alias string (case-insensitive).

    Returns:
        (canonical_name, AlgorithmEntry) if found, (None, None) otherwise.
    """
    canonical = _ALIAS_TO_CANONICAL.get(raw_name.lower().strip())
    if canonical:
        return canonical, ALGORITHM_REGISTRY[canonical]
    return None, None
