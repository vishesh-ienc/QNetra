"""
QNetra Cryptographic Knowledge Registry — Regex Pattern Signatures

Defines the CryptoPatternRegistry: a structured, maintainable collection of
compiled regex patterns for detecting cryptographic indicators across source
code and configuration files.

Pattern design principles:
  - Use word boundaries (\b) to avoid matching substrings of unrelated words.
  - Patterns are organized by category.
  - Each pattern has explicit confidence and context metadata.
  - Patterns are compiled once at module import (not per-scan).
  - Comment-line patterns have lower confidence than executable code patterns.

IMPORTANT: Regex patterns have higher false-positive risk than AST analysis.
A regex match in executable code has MEDIUM confidence (0.60-0.75).
A regex match in a comment has LOW confidence (0.15-0.35).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CryptoPattern:
    """A single compiled regex pattern for cryptographic indicator detection."""
    name: str                    # Human-readable pattern name
    pattern: re.Pattern          # Compiled regex
    algorithm: Optional[str]     # Canonical algorithm name (or None if generic)
    category: str                # ArtifactCategory value
    base_confidence: float       # Confidence for a match in executable code context
    comment_confidence: float    # Confidence for a match in comment context
    description: str = ""


def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Algorithm Identifier Patterns
# ---------------------------------------------------------------------------

ALGORITHM_PATTERNS: list[CryptoPattern] = [
    CryptoPattern(
        name="RSA_identifier",
        pattern=_compile(r'\bRSA[-_]?(\d{1,5})\b'),
        algorithm="RSA",
        category="ASYMMETRIC_PKC",
        base_confidence=0.72,
        comment_confidence=0.25,
        description="RSA with key size (e.g. RSA-2048, RSA_4096).",
    ),
    CryptoPattern(
        name="RSA_generic",
        pattern=_compile(r'\bRSA\b'),
        algorithm="RSA",
        category="ASYMMETRIC_PKC",
        base_confidence=0.60,
        comment_confidence=0.20,
    ),
    CryptoPattern(
        name="AES_with_params",
        pattern=_compile(r'\bAES[-_]?(128|192|256)[-_]?(CBC|GCM|CTR|CFB|OFB|ECB|CCM|SIV)?\b'),
        algorithm="AES",
        category="SYMMETRIC_CIPHER",
        base_confidence=0.78,
        comment_confidence=0.30,
        description="AES with key size and optional mode (e.g. AES-256-GCM).",
    ),
    CryptoPattern(
        name="AES_generic",
        pattern=_compile(r'\bAES\b'),
        algorithm="AES",
        category="SYMMETRIC_CIPHER",
        base_confidence=0.62,
        comment_confidence=0.22,
    ),
    CryptoPattern(
        name="SHA256_variants",
        pattern=_compile(r'\bSHA[-_]?256\b'),
        algorithm="SHA-256",
        category="HASH_FUNCTION",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="SHA512_variants",
        pattern=_compile(r'\bSHA[-_]?512\b'),
        algorithm="SHA-512",
        category="HASH_FUNCTION",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="SHA1_variants",
        pattern=_compile(r'\bSHA[-_]?1\b'),
        algorithm="SHA-1",
        category="HASH_FUNCTION",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="SHA384_variants",
        pattern=_compile(r'\bSHA[-_]?384\b'),
        algorithm="SHA-384",
        category="HASH_FUNCTION",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="SHA3_variants",
        pattern=_compile(r'\bSHA[-_]?3[-_]?(224|256|384|512)?\b'),
        algorithm="SHA-3",
        category="HASH_FUNCTION",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="MD5",
        pattern=_compile(r'\bMD[-_]?5\b'),
        algorithm="MD5",
        category="HASH_FUNCTION",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="DES_triple",
        pattern=_compile(r'\b(3DES|3-DES|TripleDES|Triple-DES|DES-EDE|DES-EDE3|TDES|TDEA)\b'),
        algorithm="3DES",
        category="SYMMETRIC_CIPHER",
        base_confidence=0.75,
        comment_confidence=0.30,
    ),
    CryptoPattern(
        name="DES_single",
        pattern=_compile(r'\bDES\b'),
        algorithm="DES",
        category="SYMMETRIC_CIPHER",
        base_confidence=0.65,
        comment_confidence=0.22,
        description="Single DES — beware false positives from 'DESCRIBES', filter with word boundary.",
    ),
    CryptoPattern(
        name="ECDSA_variants",
        pattern=_compile(r'\b(ECDSA|EC-DSA|elliptic.curve|secp256r1|secp384r1|secp521r1|prime256v1)\b'),
        algorithm="ECDSA",
        category="ASYMMETRIC_PKC",
        base_confidence=0.75,
        comment_confidence=0.28,
    ),
    CryptoPattern(
        name="ECDH_variants",
        pattern=_compile(r'\b(ECDHE?|X25519|X448|ECDH)\b'),
        algorithm="ECDH",
        category="KEY_EXCHANGE",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="ED25519",
        pattern=_compile(r'\b(Ed25519|Edwards25519|EdDSA)\b'),
        algorithm="ED25519",
        category="DIGITAL_SIGNATURE",
        base_confidence=0.75,
        comment_confidence=0.28,
    ),
    CryptoPattern(
        name="RSA_modes",
        pattern=_compile(r'\b(PKCS1[-_]?(v1_5|OAEP)?|OAEP|PSS|RSAES|RSASSA)\b'),
        algorithm="RSA",
        category="ASYMMETRIC_PKC",
        base_confidence=0.68,
        comment_confidence=0.22,
    ),
    CryptoPattern(
        name="AES_cipher_modes",
        pattern=_compile(r'\b(AES\.MODE_GCM|AES\.MODE_CBC|AES\.MODE_CTR|AES\.MODE_ECB|AES\.MODE_CFB|AES\.MODE_OFB|AES\.MODE_CCM)\b'),
        algorithm="AES",
        category="SYMMETRIC_CIPHER",
        base_confidence=0.88,
        comment_confidence=0.35,
        description="Python PyCryptodome mode constants — high confidence.",
    ),
    CryptoPattern(
        name="HMAC_identifier",
        pattern=_compile(r'\bHMAC[-_]?(SHA\d{1,3}|MD5)?\b'),
        algorithm="HMAC",
        category="MAC",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="RC4_identifier",
        pattern=_compile(r'\b(RC4|ARCFOUR|ARC4)\b'),
        algorithm="RC4",
        category="SYMMETRIC_CIPHER",
        base_confidence=0.75,
        comment_confidence=0.28,
    ),
]

# ---------------------------------------------------------------------------
# PEM / Key Material Patterns
# ---------------------------------------------------------------------------

KEY_MATERIAL_PATTERNS: list[CryptoPattern] = [
    CryptoPattern(
        name="PEM_private_key",
        pattern=_compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'),
        algorithm="RSA",
        category="KEY_MATERIAL",
        base_confidence=0.97,
        comment_confidence=0.90,
        description="PEM-encoded private key block — very high confidence.",
    ),
    CryptoPattern(
        name="PEM_ec_private_key",
        pattern=_compile(r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----'),
        algorithm="ECDSA",
        category="KEY_MATERIAL",
        base_confidence=0.97,
        comment_confidence=0.90,
    ),
    CryptoPattern(
        name="PEM_public_key",
        pattern=_compile(r'-----BEGIN\s+PUBLIC\s+KEY-----'),
        algorithm=None,
        category="KEY_MATERIAL",
        base_confidence=0.90,
        comment_confidence=0.80,
    ),
    CryptoPattern(
        name="PEM_certificate",
        pattern=_compile(r'-----BEGIN\s+CERTIFICATE-----'),
        algorithm=None,
        category="CERTIFICATE",
        base_confidence=0.93,
        comment_confidence=0.85,
    ),
    CryptoPattern(
        name="SSH_private_key",
        pattern=_compile(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----'),
        algorithm=None,
        category="KEY_MATERIAL",
        base_confidence=0.97,
        comment_confidence=0.90,
    ),
]

# ---------------------------------------------------------------------------
# TLS / Protocol Patterns
# ---------------------------------------------------------------------------

PROTOCOL_PATTERNS: list[CryptoPattern] = [
    CryptoPattern(
        name="TLS_cipher_suite",
        pattern=_compile(r'\bTLS_(?:RSA|DHE|ECDHE)_WITH_[A-Z0-9_]+\b'),
        algorithm="TLS",
        category="PROTOCOL",
        base_confidence=0.80,
        comment_confidence=0.35,
        description="Full TLS cipher suite name (e.g. TLS_RSA_WITH_AES_128_CBC_SHA).",
    ),
    CryptoPattern(
        name="SSL_version_dangerous",
        pattern=_compile(r'\b(SSLv2|SSLv3|SSL2|SSL3|SSLv2_client|SSLv3_client)\b'),
        algorithm="SSL",
        category="PROTOCOL",
        base_confidence=0.85,
        comment_confidence=0.40,
        description="Dangerous SSL versions — completely broken.",
    ),
    CryptoPattern(
        name="TLS_version_old",
        pattern=_compile(r'\b(TLSv1(?:\.0)?|TLS_v1(?:_0)?|TLSv1_0|tlsv1_client_method)\b', re.IGNORECASE),
        algorithm="TLS",
        category="PROTOCOL",
        base_confidence=0.80,
        comment_confidence=0.32,
        description="TLS 1.0 — deprecated by RFC 8996.",
    ),
    CryptoPattern(
        name="JWT_alg",
        pattern=_compile(r'"alg"\s*:\s*"(HS256|HS512|RS256|RS512|ES256|ES512|PS256|none)"'),
        algorithm=None,
        category="DIGITAL_SIGNATURE",
        base_confidence=0.82,
        comment_confidence=0.35,
        description="JWT algorithm field in JSON — extractable from capture group.",
    ),
]

# ---------------------------------------------------------------------------
# KDF Patterns
# ---------------------------------------------------------------------------

KDF_PATTERNS: list[CryptoPattern] = [
    CryptoPattern(
        name="PBKDF2_identifier",
        pattern=_compile(r'\bPBKDF2[-_]?HMAC?\b'),
        algorithm="PBKDF2",
        category="KDF",
        base_confidence=0.78,
        comment_confidence=0.28,
    ),
    CryptoPattern(
        name="bcrypt_identifier",
        pattern=_compile(r'\bbcrypt\b'),
        algorithm="bcrypt",
        category="KDF",
        base_confidence=0.72,
        comment_confidence=0.25,
    ),
    CryptoPattern(
        name="argon2_identifier",
        pattern=_compile(r'\bargon2(id|i|d)?\b'),
        algorithm="Argon2",
        category="KDF",
        base_confidence=0.75,
        comment_confidence=0.28,
    ),
    CryptoPattern(
        name="scrypt_identifier",
        pattern=_compile(r'\bscrypt\b'),
        algorithm="scrypt",
        category="KDF",
        base_confidence=0.70,
        comment_confidence=0.25,
    ),
]

# ---------------------------------------------------------------------------
# PQC Patterns (detect adoption of post-quantum algorithms)
# ---------------------------------------------------------------------------

PQC_PATTERNS: list[CryptoPattern] = [
    CryptoPattern(
        name="ML_KEM_identifier",
        pattern=_compile(r'\b(ML[-_]KEM|mlkem|kyber|crystals[-_]kyber)\b'),
        algorithm="ML-KEM",
        category="KEY_EXCHANGE",
        base_confidence=0.82,
        comment_confidence=0.35,
    ),
    CryptoPattern(
        name="ML_DSA_identifier",
        pattern=_compile(r'\b(ML[-_]DSA|mldsa|dilithium|crystals[-_]dilithium)\b'),
        algorithm="ML-DSA",
        category="DIGITAL_SIGNATURE",
        base_confidence=0.82,
        comment_confidence=0.35,
    ),
    CryptoPattern(
        name="SLH_DSA_identifier",
        pattern=_compile(r'\b(SLH[-_]DSA|slhdsa|sphincs\+?|SPHINCS)\b'),
        algorithm="SLH-DSA",
        category="DIGITAL_SIGNATURE",
        base_confidence=0.82,
        comment_confidence=0.35,
    ),
]

# ---------------------------------------------------------------------------
# Unified registry
# ---------------------------------------------------------------------------

ALL_PATTERNS: list[CryptoPattern] = (
    ALGORITHM_PATTERNS +
    KEY_MATERIAL_PATTERNS +
    PROTOCOL_PATTERNS +
    KDF_PATTERNS +
    PQC_PATTERNS
)


def is_comment_line(line: str, language: str = "python") -> bool:
    """
    Heuristic check whether a source line is primarily a comment.
    Patterns matched in comments receive lower confidence.
    """
    stripped = line.strip()
    if language in ("python",):
        return stripped.startswith("#")
    if language in ("javascript", "java", "cpp", "c"):
        return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")
    return False
