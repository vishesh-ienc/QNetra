"""
QNetra Normalization Subsystem — Algorithm & Parameter Normalizer
=================================================================

Handles deterministic canonicalization of:
  - Cryptographic algorithm names & aliases (e.g. 'AES_256_GCM' -> 'AES-256-GCM')
  - Algorithm family classification (e.g. 'AES', 'RSA', 'SHA', 'ECC')
  - Functional primitive categories (PrimitiveType)
  - Key size, cipher mode, elliptic curve, padding, and library hints

Contracts:
  - docs/06_API_AND_DATA_CONTRACTS.md
  - docs/05_ALGORITHMS.md
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple, Optional

from core.models import PrimitiveType
from scanners.framework.models import ArtifactCategory, RawFinding
from scanners.registry.crypto_algorithms import ALGORITHM_REGISTRY, resolve_algorithm


class NormalizedAttributes(NamedTuple):
    """Normalized technical cryptographic properties."""
    algorithm: str
    algorithm_family: Optional[str]
    primitive_type: PrimitiveType
    key_length_bits: Optional[int]
    curve: Optional[str]
    mode: Optional[str]
    padding: Optional[str]
    implementation_library: Optional[str]


# ---------------------------------------------------------------------------
# Canonical Curve Maps
# ---------------------------------------------------------------------------
_CURVE_ALIAS_MAP: dict[str, str] = {
    "secp256r1": "secp256r1",
    "prime256v1": "secp256r1",
    "p-256": "secp256r1",
    "p256": "secp256r1",
    "secp384r1": "secp384r1",
    "p-384": "secp384r1",
    "p384": "secp384r1",
    "secp521r1": "secp521r1",
    "p-521": "secp521r1",
    "p521": "secp521r1",
    "secp256k1": "secp256k1",
    "curve25519": "Curve25519",
    "x25519": "Curve25519",
    "ed25519": "Ed25519",
    "edwards25519": "Ed25519",
    "brainpoolp256r1": "brainpoolP256r1",
    "brainpoolp384r1": "brainpoolP384r1",
    "brainpoolp512r1": "brainpoolP512r1",
}

# ---------------------------------------------------------------------------
# Cipher Mode Maps
# ---------------------------------------------------------------------------
_MODE_MAP: dict[str, str] = {
    "gcm": "GCM",
    "cbc": "CBC",
    "ctr": "CTR",
    "ecb": "ECB",
    "cfb": "CFB",
    "ofb": "OFB",
    "ccm": "CCM",
    "xts": "XTS",
}

# ---------------------------------------------------------------------------
# Padding Maps
# ---------------------------------------------------------------------------
_PADDING_MAP: dict[str, str] = {
    "pkcs5padding": "PKCS7",
    "pkcs7padding": "PKCS7",
    "pkcs7": "PKCS7",
    "pkcs5": "PKCS7",
    "nopadding": "NoPadding",
    "pkcs1padding": "PKCS1v15",
    "pkcs1_oaep": "PKCS1_OAEP",
    "oaep": "PKCS1_OAEP",
    "pss": "PSS",
}

# ---------------------------------------------------------------------------
# Library Normalization Map
# ---------------------------------------------------------------------------
_LIBRARY_NORM_MAP: dict[str, str] = {
    "javax.crypto": "javax.crypto",
    "java.security": "java.security",
    "bouncycastle": "BouncyCastle",
    "bcprov": "BouncyCastle",
    "pycryptodome": "pycryptodome",
    "cryptodome": "pycryptodome",
    "cryptography": "cryptography",
    "crypto-js": "crypto-js",
    "node:crypto": "Node.js crypto",
    "node-forge": "node-forge",
    "openssl": "OpenSSL",
    "libcrypto": "OpenSSL",
    "libssl": "OpenSSL",
    "libssl3": "OpenSSL",
    "libsodium": "libsodium",
    "sodium": "libsodium",
    "mbedtls": "mbedTLS",
    "hashlib": "hashlib",
    "hmac": "hmac",
    "bcrypt": "bcrypt",
    "paramiko": "paramiko",
    "jsonwebtoken": "jsonwebtoken",
}


class AlgorithmNormalizer:
    """
    Normalizes raw cryptographic indicators into canonical names and technical parameters.
    """

    @staticmethod
    def normalize_finding(finding: RawFinding) -> NormalizedAttributes:
        """
        Derive standard cryptographic attributes from a RawFinding.
        """
        raw_sym = (finding.raw_symbol or "").strip()
        suspected = (finding.suspected_algorithm or "").strip()
        category = finding.artifact_category
        key_size = finding.key_size_hint
        mode = (finding.mode_hint or "").strip().upper() if finding.mode_hint else None
        curve = (finding.curve_hint or "").strip() if finding.curve_hint else None
        padding: Optional[str] = None
        library = AlgorithmNormalizer._normalize_library(finding.library_hint)

        # 1. Parse Java JCA algorithm transformation format: e.g. "AES/CBC/PKCS5Padding"
        jca_alg, jca_mode, jca_pad = AlgorithmNormalizer._parse_jca_pattern(raw_sym)
        if not jca_alg and suspected:
            jca_alg, jca_mode, jca_pad = AlgorithmNormalizer._parse_jca_pattern(suspected)
        if jca_alg:
            suspected = jca_alg
            if jca_mode and not mode:
                mode = jca_mode
            if jca_pad and not padding:
                padding = jca_pad

        # 2. Parse OpenSSL EVP symbols: e.g. "EVP_aes_256_gcm", "EVP_sha256"
        evp_alg, evp_key, evp_mode = AlgorithmNormalizer._parse_openssl_evp(raw_sym)
        if not evp_alg and suspected:
            evp_alg, evp_key, evp_mode = AlgorithmNormalizer._parse_openssl_evp(suspected)
        if evp_alg:
            if not suspected or suspected.upper().startswith("EVP") or suspected.upper() in ("AES", "SHA", "RSA", "HASH"):
                suspected = evp_alg
            if evp_key and not key_size:
                key_size = evp_key
            if evp_mode and not mode:
                mode = evp_mode

        # 3. Extract embedded parameters from suspected algorithm string (e.g. "AES-256-GCM", "RSA-2048")
        extracted_alg, ext_key, ext_mode = AlgorithmNormalizer._extract_parameters_from_string(suspected)
        if ext_key and not key_size:
            key_size = ext_key
        if ext_mode and not mode:
            mode = ext_mode
        if extracted_alg:
            suspected = extracted_alg

        # Also inspect raw_symbol for embedded key sizes (e.g. RSA.generate(2048))
        # IMPORTANT: Only extract RSA/DSA/DH key sizes from structured word-boundary patterns.
        # AES key sizes MUST NOT be inferred from numbers appearing in raw_sym text —
        # digits like 128, 192, 256 can appear in unrelated contexts (line numbers, comments,
        # hex addresses, unrelated constants). AES key size must be explicitly provided via
        # key_size_hint or parsed from a structured algorithm string (e.g. "AES-256-GCM").
        # Violating this rule silently fabricates key sizes that corrupt downstream classification.
        if not key_size and raw_sym:
            key_match = re.search(r"\b(512|1024|2048|3072|4096)\b", raw_sym)
            if key_match and ("RSA" in suspected.upper() or "DSA" in suspected.upper() or "DH" in suspected.upper()):
                key_size = int(key_match.group(1))

        # 4. Normalize curve aliases
        if curve:
            curve = _CURVE_ALIAS_MAP.get(curve.lower(), curve)
        elif raw_sym:
            for curve_alias, canon_curve in _CURVE_ALIAS_MAP.items():
                if re.search(rf"\b{re.escape(curve_alias)}\b", raw_sym, re.IGNORECASE):
                    curve = canon_curve
                    break

        # If suspected algorithm is itself an ECC curve name, resolve to the appropriate algorithm
        if suspected and suspected.lower() in _CURVE_ALIAS_MAP:
            if not curve:
                curve = _CURVE_ALIAS_MAP[suspected.lower()]
            if suspected.lower() in ("x25519", "curve25519"):
                suspected = "ECDH"
            elif suspected.lower() in ("ed25519", "edwards25519"):
                suspected = "Ed25519"
            else:
                suspected = "ECDSA"

        # 5. Normalize cipher mode
        if mode:
            mode = _MODE_MAP.get(mode.lower(), mode)

        # 6. Normalize padding
        if padding:
            padding = _PADDING_MAP.get(padding.lower(), padding)

        # 7. Canonicalize algorithm name and family
        canonical_alg, family = AlgorithmNormalizer._canonicalize_algorithm_name(
            suspected=suspected,
            raw_symbol=raw_sym,
            category=category,
            key_size=key_size,
            mode=mode,
            curve=curve,
            library=library,
        )

        # 8. Map to canonical PrimitiveType
        prim_type = AlgorithmNormalizer._determine_primitive_type(
            category=category,
            family=family,
            canonical_alg=canonical_alg,
            raw_sym=raw_sym,
        )

        return NormalizedAttributes(
            algorithm=canonical_alg,
            algorithm_family=family,
            primitive_type=prim_type,
            key_length_bits=key_size,
            curve=curve,
            mode=mode,
            padding=padding,
            implementation_library=library,
        )

    @staticmethod
    def _parse_jca_pattern(symbol: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Parse Java Cryptography Architecture transformations like 'AES/CBC/PKCS5Padding'."""
        match = re.search(r'["\']?([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)["\']?', symbol)
        if match:
            alg, mode, pad = match.group(1), match.group(2).upper(), match.group(3)
            mode_norm = _MODE_MAP.get(mode.lower(), mode)
            pad_norm = _PADDING_MAP.get(pad.lower(), pad)
            return alg, mode_norm, pad_norm

        match_two = re.search(r'["\']?([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)["\']?', symbol)
        if match_two:
            alg, mode = match_two.group(1), match_two.group(2).upper()
            mode_norm = _MODE_MAP.get(mode.lower(), mode)
            return alg, mode_norm, None

        return None, None, None

    @staticmethod
    def _parse_openssl_evp(symbol: str) -> tuple[Optional[str], Optional[int], Optional[str]]:
        """Parse OpenSSL EVP function names like 'EVP_aes_256_gcm' or 'EVP_sha256'."""
        if not symbol or "EVP_" not in symbol:
            return None, None, None

        # EVP_aes_256_gcm
        m_aes = re.search(r"EVP_aes_(\d{3})_([a-z0-9]+)", symbol, re.IGNORECASE)
        if m_aes:
            k = int(m_aes.group(1))
            m = m_aes.group(2).upper()
            return f"AES-{k}-{m}", k, m

        # EVP_sha256, EVP_sha384, EVP_sha512, EVP_sha1, EVP_md5
        m_hash = re.search(r"EVP_(sha\d+|sha3_\d+|md5)", symbol, re.IGNORECASE)
        if m_hash:
            h = m_hash.group(1).upper()
            if h.startswith("SHA") and not h.startswith("SHA-") and len(h) > 3:
                h = f"SHA-{h[3:]}"
            return h, None, None

        # EVP_PKEY_RSA, EVP_PKEY_EC, RSA_generate_key
        if "RSA" in symbol.upper():
            return "RSA", None, None
        if "EC" in symbol.upper():
            return "ECDSA", None, None

        return None, None, None

    @staticmethod
    def _extract_parameters_from_string(s: str) -> tuple[str, Optional[int], Optional[str]]:
        """Extract key size and mode from STRUCTURED algorithm name strings only.

        Handles these structured algorithm naming forms:
          'AES-256-GCM', 'AES_128_CBC' -> AES, 256/128, GCM/CBC
          'AES-256', 'AES-128'         -> AES, 256/128, None
          'aes256', 'aes128', 'aes192' -> AES, 256/128/192, None (concatenated alias)
          'aes256gcm', 'aes128cbc'     -> AES, 256/128, GCM/CBC (concatenated compound)
          'AES-GCM', 'AES-CBC'         -> AES, None, GCM/CBC
          'RSA-2048', 'RSA-4096'       -> RSA, 2048/4096, None
          'SHA256', 'SHA512'           -> SHA-256, SHA-512, None

        CRITICAL: This method ONLY extracts from the algorithm name string itself.
        It does NOT scan raw source code, snippets, comments, or surrounding context.
        Numbers must be part of a recognized algorithm-name pattern to be extracted.
        """
        if not s:
            return "", None, None

        # Standardize separators (underscore -> hyphen) for pattern matching
        normalized = s.replace("_", "-")

        # AES with key and mode (separator-delimited): AES-256-GCM, AES-128-CBC
        m_aes = re.match(r"^AES-(128|192|256)-([A-Z0-9]+)$", normalized, re.IGNORECASE)
        if m_aes:
            return "AES", int(m_aes.group(1)), m_aes.group(2).upper()

        # AES with key only (separator-delimited): AES-256, AES-128, AES-192
        m_aes_key = re.match(r"^AES-(128|192|256)$", normalized, re.IGNORECASE)
        if m_aes_key:
            return "AES", int(m_aes_key.group(1)), None

        # AES concatenated with valid key size: aes256, aes128, aes192
        # Also handles compound forms: aes256gcm, aes128cbc
        # Only matches valid AES key sizes (128, 192, 256) — not arbitrary numbers.
        m_aes_concat = re.match(r"^AES(128|192|256)([A-Z]{2,4})?$", normalized, re.IGNORECASE)
        if m_aes_concat:
            key = int(m_aes_concat.group(1))
            mode_raw = m_aes_concat.group(2)
            mode = _MODE_MAP.get(mode_raw.lower(), mode_raw.upper()) if mode_raw else None
            return "AES", key, mode

        # AES with mode only (no key size): AES-GCM, AES-CBC
        m_aes_mode = re.match(r"^AES-([A-Z]{3,4})$", normalized, re.IGNORECASE)
        if m_aes_mode:
            return "AES", None, m_aes_mode.group(1).upper()

        # RSA with specific key sizes: RSA-2048, RSA-4096, RSA-1024, RSA-3072
        m_rsa = re.match(r"^RSA-(512|1024|2048|3072|4096|7680|15360)$", normalized, re.IGNORECASE)
        if m_rsa:
            return "RSA", int(m_rsa.group(1)), None

        # SHA variants: SHA256 -> SHA-256, SHA512 -> SHA-512
        m_sha = re.match(r"^SHA(\d{3})$", normalized, re.IGNORECASE)
        if m_sha:
            return f"SHA-{m_sha.group(1)}", None, None

        return s, None, None

    @staticmethod
    def _canonicalize_algorithm_name(
        suspected: str,
        raw_symbol: str,
        category: ArtifactCategory,
        key_size: Optional[int],
        mode: Optional[str],
        curve: Optional[str],
        library: Optional[str],
    ) -> tuple[str, Optional[str]]:
        """
        Determine canonical algorithm display name and high-level family.
        """
        cleaned = suspected.strip().replace("_", "-") if suspected else ""

        # Check knowledge base registry lookup
        if cleaned:
            reg_canon, entry = resolve_algorithm(cleaned)
            if reg_canon:
                family = reg_canon.upper()
                # Refine AES canonical representation
                if family == "AES":
                    if key_size and mode:
                        return f"AES-{key_size}-{mode}", "AES"
                    elif mode:
                        return f"AES-{mode}", "AES"
                    elif key_size:
                        return f"AES-{key_size}", "AES"
                    return "AES", "AES"
                elif family == "RSA":
                    return "RSA", "RSA"
                elif family in ("SHA-256", "SHA-384", "SHA-512", "SHA-1", "SHA-3"):
                    return entry.canonical_name, "SHA"
                elif family in ("ECDSA", "ECDH", "ED25519"):
                    return entry.canonical_name, "ECC"
                return entry.canonical_name, family

        # Fallback based on raw_symbol or category if suspected is missing
        if not cleaned:
            if category == ArtifactCategory.CERTIFICATE:
                return "X.509 Certificate", "CERTIFICATE"
            if category == ArtifactCategory.KEY_MATERIAL:
                return "Cryptographic Key Material", "KEY_MATERIAL"
            if category == ArtifactCategory.LIBRARY:
                lib_name = library or "Cryptographic Library"
                return f"Library: {lib_name}", "LIBRARY"
            if category == ArtifactCategory.RANDOM:
                return "CSPRNG", "RANDOM"
            if category == ArtifactCategory.PROTOCOL:
                if "TLS" in raw_symbol.upper():
                    return "TLS", "PROTOCOL"
                if "SSH" in raw_symbol.upper():
                    return "SSH", "PROTOCOL"
                if "SSL" in raw_symbol.upper():
                    return "SSL", "PROTOCOL"

            # Check raw symbol content
            upper_raw = raw_symbol.upper()
            if "RSA" in upper_raw:
                return "RSA", "RSA"
            if "AES" in upper_raw:
                if key_size and mode:
                    return f"AES-{key_size}-{mode}", "AES"
                return "AES", "AES"
            if "SHA256" in upper_raw or "SHA-256" in upper_raw:
                return "SHA-256", "SHA"
            if "HMAC" in upper_raw:
                return "HMAC", "MAC"
            if "PBKDF2" in upper_raw:
                return "PBKDF2", "KDF"
            if "BCRYPT" in upper_raw:
                return "bcrypt", "KDF"
            if "SECP256R1" in upper_raw or "PRIME256V1" in upper_raw:
                return "ECDSA", "ECC"

            return "Unknown Algorithm", None

        upper_c = cleaned.upper()
        if upper_c.startswith("ML-KEM"):
            return "ML-KEM", "ML-KEM"
        if upper_c.startswith("ML-DSA"):
            return "ML-DSA", "ML-DSA"
        if upper_c.startswith("SLH-DSA"):
            return "SLH-DSA", "SLH-DSA"
        if upper_c.startswith("SHA-") or upper_c.startswith("SHA3"):
            return cleaned, "SHA"
        if upper_c.startswith("TLS"):
            return "TLS", "PROTOCOL"
        if upper_c.startswith("SSL"):
            return "SSL", "PROTOCOL"

        # Return cleaned name with derived family
        family = cleaned.split("-")[0].upper() if "-" in cleaned else cleaned.upper()
        return cleaned, family

    @staticmethod
    def _determine_primitive_type(
        category: ArtifactCategory,
        family: Optional[str],
        canonical_alg: str,
        raw_sym: str,
    ) -> PrimitiveType:
        """Map artifact category and algorithm properties to PrimitiveType."""
        upper_alg = canonical_alg.upper()
        upper_fam = (family or "").upper()

        if category == ArtifactCategory.LIBRARY:
            return PrimitiveType.LIBRARY
        if category == ArtifactCategory.CERTIFICATE:
            return PrimitiveType.CERTIFICATE
        if category == ArtifactCategory.KEY_MATERIAL:
            return PrimitiveType.KEY_MATERIAL
        if category == ArtifactCategory.RANDOM:
            return PrimitiveType.RANDOM
        if category == ArtifactCategory.PROTOCOL or upper_fam == "PROTOCOL" or upper_alg in ("TLS", "SSL", "SSH"):
            return PrimitiveType.PROTOCOL

        if upper_fam == "AES" or "CHACHA" in upper_fam or upper_fam in ("DES", "3DES", "RC4"):
            return PrimitiveType.SYMMETRIC_CIPHER

        if upper_fam in ("SHA", "MD5") or "SHA-" in upper_alg:
            return PrimitiveType.HASH_FUNCTION

        if upper_fam == "HMAC" or "MAC" in upper_fam or "POLY1305" in upper_fam:
            return PrimitiveType.MAC

        if upper_fam in ("PBKDF2", "BCRYPT", "SCRYPT", "ARGON2", "HKDF"):
            return PrimitiveType.KDF

        if upper_fam in ("ECDH", "DH", "X25519", "ML-KEM") or upper_alg in ("ECDH", "DH", "X25519", "ML-KEM"):
            return PrimitiveType.KEY_EXCHANGE

        if upper_fam in ("ECDSA", "ED25519", "DSA", "ML-DSA", "SLH-DSA") or upper_alg in ("ECDSA", "ED25519", "DSA", "ML-DSA", "SLH-DSA"):
            return PrimitiveType.DIGITAL_SIGNATURE

        if upper_fam == "RSA":
            if "SIGN" in raw_sym.upper() or "PSS" in raw_sym.upper():
                return PrimitiveType.DIGITAL_SIGNATURE
            return PrimitiveType.ASYMMETRIC_ENCRYPTION

        if category == ArtifactCategory.ASYMMETRIC_PKC:
            return PrimitiveType.ASYMMETRIC_ENCRYPTION
        if category == ArtifactCategory.SYMMETRIC_CIPHER:
            return PrimitiveType.SYMMETRIC_CIPHER
        if category == ArtifactCategory.HASH_FUNCTION:
            return PrimitiveType.HASH_FUNCTION
        if category == ArtifactCategory.DIGITAL_SIGNATURE:
            return PrimitiveType.DIGITAL_SIGNATURE
        if category == ArtifactCategory.KEY_EXCHANGE:
            return PrimitiveType.KEY_EXCHANGE

        return PrimitiveType.UNKNOWN

    @staticmethod
    def _normalize_library(hint: Optional[str]) -> Optional[str]:
        """Map library aliases to canonical names."""
        if not hint:
            return None
        cleaned = hint.strip()
        lower = cleaned.lower()
        if lower in _LIBRARY_NORM_MAP:
            return _LIBRARY_NORM_MAP[lower]
        # Match longer aliases first to avoid generic substrings prematurely matching
        for alias in sorted(_LIBRARY_NORM_MAP.keys(), key=len, reverse=True):
            if alias in lower:
                return _LIBRARY_NORM_MAP[alias]
        if lower == "crypto":
            return "Node.js crypto"
        return cleaned

