"""
QNetra Sample: Python Cryptographic Code — Intentionally Vulnerable
This file demonstrates multiple cryptographic patterns that QNetra should discover.
Used as a test fixture for the Repository Scanner.
"""

# Standard library crypto imports
import hashlib
import hmac
import ssl

# Third-party crypto imports (PyCryptodome)
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, MD5, SHA512
from Crypto.Random import get_random_bytes

# Third-party (PyCA cryptography)
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================================
# RSA Key Generation — Quantum Vulnerable (Shor's Algorithm)
# ============================================================

def generate_rsa_key_pycryptodome():
    """Generate RSA-2048 keypair — QUANTUM VULNERABLE."""
    key = RSA.generate(2048, e=65537)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    return private_key_pem, public_key_pem


def generate_rsa_key_pyca():
    """Generate RSA-4096 keypair via PyCA — still QUANTUM VULNERABLE despite larger key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    return private_key


def rsa_encrypt(public_key_pem: bytes, plaintext: bytes) -> bytes:
    """RSA OAEP encryption — QUANTUM VULNERABLE."""
    key = RSA.import_key(public_key_pem)
    cipher = pkcs1_15.new(key)
    return cipher.sign(SHA256.new(plaintext))


# ============================================================
# AES Encryption — Grover-Impacted (AES-128: 64-bit quantum security)
# ============================================================

def encrypt_aes_128_cbc(data: bytes, key: bytes) -> tuple:
    """AES-128-CBC encryption — Grover reduces to 64-bit quantum security."""
    key_128 = key[:16]  # 128-bit key
    cipher = AES.new(key_128, AES.MODE_CBC)
    # CBC mode — no authentication, vulnerable to padding oracle attacks
    ct = cipher.encrypt(data + b'\x00' * (16 - len(data) % 16))
    return ct, cipher.iv


def encrypt_aes_256_gcm(data: bytes, key: bytes) -> tuple:
    """AES-256-GCM — Grover reduces to 128-bit quantum security (ACCEPTABLE)."""
    key_256 = key[:32]  # 256-bit key
    cipher = AES.new(key_256, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct, tag, cipher.nonce


def encrypt_with_pyca_aes(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC via PyCA cryptography library."""
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# ============================================================
# Hash Functions — Broken and Deprecated
# ============================================================

def hash_data_md5(data: bytes) -> str:
    """MD5 hash — CLASSICALLY BROKEN (collision attacks)."""
    return hashlib.md5(data).hexdigest()


def hash_data_sha1(data: bytes) -> str:
    """SHA-1 hash — CLASSICALLY BROKEN (SHAttered attack 2017)."""
    return hashlib.sha1(data).hexdigest()


def hash_data_sha256(data: bytes) -> str:
    """SHA-256 — acceptable pre-quantum, Grover reduces to ~85-bit quantum."""
    return hashlib.sha256(data).hexdigest()


def hash_data_sha512(data: bytes) -> str:
    """SHA-512 — quantum resistant (~256-bit quantum collision resistance)."""
    return hashlib.sha512(data).hexdigest()


# ============================================================
# HMAC — Security depends on underlying hash
# ============================================================

def compute_hmac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, message, digestmod="sha256").digest()


# ============================================================
# Key Derivation — Weak parameters example
# ============================================================

def derive_key_pbkdf2(password: bytes, salt: bytes) -> bytes:
    """PBKDF2 with low iterations — INSECURE configuration."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000,  # WAY too low — should be >= 600,000
    )
    return kdf.derive(password)


# ============================================================
# ECDSA — Quantum Vulnerable
# ============================================================

def generate_ec_key():
    """EC keypair on secp256r1 (P-256) — QUANTUM VULNERABLE."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key


def sign_with_ecdsa(private_key, data: bytes) -> bytes:
    """ECDSA signature — QUANTUM VULNERABLE."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


# ============================================================
# TLS Configuration
# ============================================================

def create_ssl_context_insecure():
    """Create SSL context — using old TLS version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # TLS 1.0 deprecated by RFC 8996
    return ctx


# ============================================================
# Hardcoded Key Material — HIGH SEVERITY finding
# ============================================================

HARDCODED_PRIVATE_KEY_PEM = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END RSA PRIVATE KEY-----
"""

HARDCODED_AES_KEY = b"thisis128bitkey!"  # 128-bit AES key in source
