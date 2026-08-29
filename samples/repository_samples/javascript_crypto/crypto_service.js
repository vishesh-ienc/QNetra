/**
 * QNetra Sample: JavaScript Cryptographic Code
 * Tests Node.js crypto module, jsonwebtoken, and pattern matching.
 * Used as a test fixture for JavaScriptAnalyzer.
 */

'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');

// ============================================================
// AES Encryption — Node.js built-in crypto
// ============================================================

/**
 * AES-128-CBC encryption — Grover reduces to 64-bit quantum security.
 * @param {Buffer} data - Plaintext
 * @param {Buffer} key  - 16-byte (128-bit) key
 * @returns {Object} {iv, encrypted}
 */
function encryptAES128CBC(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return { iv, encrypted };
}

/**
 * AES-256-GCM encryption — 128-bit post-quantum security (acceptable).
 */
function encryptAES256GCM(data, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { iv, encrypted, authTag };
}

// ============================================================
// RSA Key Generation — Quantum Vulnerable
// ============================================================

async function generateRSAKeyPair() {
    return crypto.generateKeyPair('rsa', {
        modulusLength: 2048,  // 2048-bit RSA — fully broken by Shor's algorithm
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    });
}

// ============================================================
// Hashing
// ============================================================

function hashMD5(data) {
    // MD5 is CLASSICALLY BROKEN
    return crypto.createHash('md5').update(data).digest('hex');
}

function hashSHA256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function hashSHA1(data) {
    // SHA-1 is CLASSICALLY BROKEN — SHAttered collision
    return crypto.createHash('sha1').update(data).digest('hex');
}

// ============================================================
// HMAC
// ============================================================

function createHMACSHA256(key, message) {
    return crypto.createHmac('sha256', key).update(message).digest('hex');
}

// ============================================================
// JWT — Common algorithm patterns
// ============================================================

function signJWT(payload, secret) {
    // HS256 = HMAC-SHA256 — symmetric, no quantum concern at 256-bit
    return jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: '1h' });
}

function signJWTWithRSA(payload, privateKey) {
    // RS256 = RSA-SHA256 — QUANTUM VULNERABLE (Shor's algorithm)
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// ============================================================
// PBKDF2
// ============================================================

function deriveKey(password, salt) {
    // PBKDF2-SHA256 with 310,000 iterations (OWASP 2023 recommendation)
    return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
}

// ============================================================
// CryptoJS (browser/universal library)
// ============================================================

function encryptWithCryptoJS(message, key) {
    // AES in CBC mode (CryptoJS default)
    return CryptoJS.AES.encrypt(message, key).toString();
}

function computeMD5(message) {
    // MD5 — CLASSICALLY BROKEN
    return CryptoJS.MD5(message).toString();
}

module.exports = {
    encryptAES128CBC, encryptAES256GCM, generateRSAKeyPair,
    hashMD5, hashSHA256, hashSHA1, createHMACSHA256,
    signJWT, signJWTWithRSA, deriveKey, encryptWithCryptoJS, computeMD5,
};
