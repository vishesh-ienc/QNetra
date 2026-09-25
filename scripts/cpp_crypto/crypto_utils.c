/**
 * QNetra Sample: C/C++ Cryptographic Code using OpenSSL
 * Tests OpenSSL EVP API, RSA, AES, SHA patterns and include detection.
 * Used as a test fixture for CppAnalyzer.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

/* ==========================================================
 * RSA Key Generation — Quantum Vulnerable (Shor's Algorithm)
 * ========================================================== */

RSA* generate_rsa_2048(void) {
    /* RSA-2048 is QUANTUM VULNERABLE — Shor's algorithm breaks it */
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_free(e);
    return rsa;
}

int rsa_encrypt(RSA* pub_key, const unsigned char* plaintext, int plaintext_len,
                unsigned char* ciphertext) {
    /* PKCS1 padding — QUANTUM VULNERABLE */
    return RSA_public_encrypt(plaintext_len, plaintext, ciphertext,
                               pub_key, RSA_PKCS1_OAEP_PADDING);
}

/* ==========================================================
 * AES Encryption — Grover-Impacted
 * ========================================================== */

int aes_256_cbc_encrypt(const unsigned char* plaintext, int pt_len,
                         const unsigned char* key,
                         const unsigned char* iv,
                         unsigned char* ciphertext) {
    /* AES-256-CBC — Grover reduces to 128-bit quantum security */
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);  /* 256-bit key */
    AES_cbc_encrypt(plaintext, ciphertext, pt_len, &aes_key, (unsigned char*)iv, AES_ENCRYPT);
    return pt_len;
}

int evp_aes_256_gcm_encrypt(const unsigned char* pt, int pt_len,
                              const unsigned char* key,
                              const unsigned char* iv,
                              unsigned char* ct, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ct_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

/* AES-128 — Grover reduces to 64-bit quantum security (INSUFFICIENT) */
void evp_aes_128_cbc_example(void) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_free(ctx);
}

/* ==========================================================
 * SHA Hashing
 * ========================================================== */

void sha256_hash(const unsigned char* data, size_t len, unsigned char* digest) {
    SHA256(data, len, digest);  /* SHA-256 */
}

void sha512_hash(const unsigned char* data, size_t len, unsigned char* digest) {
    SHA512(data, len, digest);  /* SHA-512 — quantum resistant */
}

void sha1_hash(const unsigned char* data, size_t len, unsigned char* digest) {
    SHA1(data, len, digest);  /* SHA-1 — CLASSICALLY BROKEN */
}

void md5_hash(const unsigned char* data, size_t len, unsigned char* digest) {
    MD5(data, len, digest);  /* MD5 — CLASSICALLY BROKEN */
}

/* ==========================================================
 * ECDSA — Quantum Vulnerable
 * ========================================================== */

EC_KEY* generate_ec_key_p256(void) {
    /* secp256r1 (P-256) — QUANTUM VULNERABLE */
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}

/* ==========================================================
 * TLS Context
 * ========================================================== */

SSL_CTX* create_tls_context(void) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    return ctx;
}
