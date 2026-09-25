/**
 * QNetra Sample: Java Cryptographic Code
 * Tests javax.crypto, java.security patterns and getInstance() calls.
 * Used as a test fixture for JavaAnalyzer.
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class CryptoService {

    // ================================================================
    // AES Encryption — Grover-Impacted
    // ================================================================

    public static byte[] encryptAES128GCM(byte[] plaintext, byte[] keyBytes) throws Exception {
        // AES-128-GCM — Grover's algorithm reduces to 64-bit quantum security
        SecretKey key = new SecretKeySpec(keyBytes, 0, 16, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }

    public static SecretKey generateAES256Key() throws Exception {
        // AES-256 key generation — Grover reduces to 128-bit quantum security
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);  // 256-bit key
        return keyGen.generateKey();
    }

    // ================================================================
    // DES Encryption — Classically Broken
    // ================================================================

    public static byte[] encryptDES(byte[] plaintext, byte[] keyBytes) throws Exception {
        // DES is CLASSICALLY BROKEN — 56-bit key, do not use
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    // ================================================================
    // RSA Key Generation — Quantum Vulnerable
    // ================================================================

    public static KeyPair generateRSA2048() throws Exception {
        // RSA-2048 — QUANTUM VULNERABLE (Shor's algorithm)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static byte[] signWithRSA(PrivateKey privateKey, byte[] data) throws Exception {
        // RSA-SHA256 signature — QUANTUM VULNERABLE
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    // ================================================================
    // ECDSA — Quantum Vulnerable
    // ================================================================

    public static KeyPair generateECDSA() throws Exception {
        // ECDSA on secp256r1 — QUANTUM VULNERABLE
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    // ================================================================
    // Message Digests — Some Broken
    // ================================================================

    public static byte[] digestMD5(byte[] data) throws Exception {
        // MD5 — CLASSICALLY BROKEN
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public static byte[] digestSHA1(byte[] data) throws Exception {
        // SHA-1 — CLASSICALLY BROKEN
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public static byte[] digestSHA256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // ================================================================
    // PBKDF2 — Key Derivation
    // ================================================================

    public static byte[] deriveKeyPBKDF2(char[] password, byte[] salt) throws Exception {
        // PBKDF2WithHmacSHA256 — KDF with SHA-256 HMAC
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(
            new javax.crypto.spec.PBEKeySpec(password, salt, 310000, 256)
        ).getEncoded();
    }
}
