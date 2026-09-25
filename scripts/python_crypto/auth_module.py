"""
QNetra Sample: Python Cryptographic Code — Auth Module
Used as a test fixture for the Repository Scanner.
Tests bcrypt, hashlib, JWT-like patterns, and config-based algorithm selection.
"""

import hashlib
import hmac
import os
import base64

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


# JWT-like HS256 configuration
JWT_ALGORITHM = "HS256"
JWT_SECRET = "my-super-secret-key-that-should-not-be-here"

# Configuration dict with algorithm names as strings
CRYPTO_CONFIG = {
    "hash_algorithm": "SHA-256",
    "sign_algorithm": "RSA-2048",
    "tls_version": "TLSv1.2",
    "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA256",
}


def hash_password_bcrypt(password: str) -> bytes:
    """bcrypt password hashing — memory-hard KDF."""
    if HAS_BCRYPT:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt)
    # Fallback: SHA-256 (not suitable for passwords!)
    return hashlib.sha256(password.encode()).digest()


def verify_password_bcrypt(password: str, hashed: bytes) -> bool:
    """bcrypt verification."""
    if HAS_BCRYPT:
        return bcrypt.checkpw(password.encode(), hashed)
    return False


def generate_token(user_id: str, secret: str) -> str:
    """Generate a simple HMAC-based token (not real JWT)."""
    # HMAC-SHA256 signature
    sig = hmac.new(
        secret.encode(),
        user_id.encode(),
        digestmod="sha256"
    ).digest()
    return base64.urlsafe_b64encode(sig).decode()


def derive_key_from_password(password: str) -> bytes:
    """PBKDF2-HMAC-SHA1 with very low iterations — INSECURE."""
    salt = os.urandom(16)
    # SHA-1 as the hash for PBKDF2 — both algorithm and iteration count are weak
    return hashlib.pbkdf2_hmac("sha1", password.encode(), salt, iterations=100)


def weak_random_key(length: int = 16) -> bytes:
    """Using os.urandom is correct, but 16 bytes = AES-128 which is Grover-impacted."""
    return os.urandom(length)


def compute_md5_checksum(data: bytes) -> str:
    """MD5 checksum — CLASSICALLY BROKEN for security purposes."""
    return hashlib.md5(data).hexdigest()
