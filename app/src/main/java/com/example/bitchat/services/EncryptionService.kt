package com.example.bitchat.services

import android.security.keystore.KeyProperties
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore // For Android Keystore interactions (though not directly used for these core crypto ops)
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.Security // To add BouncyCastle provider
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.security.spec.KeySpec

// It's highly recommended to use BouncyCastle for Ed25519 and potentially X25519 if standard JCE providers are insufficient or inconsistent.
// Add "org.bouncycastle:bcprov-jdk18on:1.77" or similar to your build.gradle
// import org.bouncycastle.jce.provider.BouncyCastleProvider
// import org.bouncycastle.jcajce.spec.XDHParameterSpec
// import org.bouncycastle.jcajce.spec.EdDSAParameterSpec

class EncryptionService {

    companion object {
        private const val TAG = "EncryptionService"
        private const val AES_KEY_SIZE = 256 // bits
        private const val GCM_IV_LENGTH = 12 // bytes (96 bits is recommended for GCM)
        private const val GCM_TAG_LENGTH = 16 // bytes (128 bits)

        private const val HKDF_ALGORITHM = "HmacSHA256"
        private const val PBE_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val PBE_ITERATION_COUNT = 65536 // Example count, should match iOS
        private const val PBE_KEY_LENGTH = 256 // bits, for AES-256

        // Ensure BouncyCastle is added as a security provider if used
        // init {
        //     Security.removeProvider("BC") // Remove to avoid conflicts if already added
        //     Security.addProvider(BouncyCastleProvider())
        // }
    }

    // --- Key Pair Generation (Curve25519 - X25519 for agreement, Ed25519 for signing) ---

    // Note: Standard JCE support for X25519/Ed25519 key pair generation can be provider-dependent.
    // BouncyCastle is a more reliable choice here. The following is a conceptual JCE approach.
    // For X25519 (Key Agreement)
    fun generateX25519KeyPair(): KeyPair? {
        return try {
            // KeyPairGenerator.getInstance("XDH", "BC") // With BouncyCastle
            // kpg.initialize(XDHParameterSpec("X25519"), SecureRandom())
            val kpg = KeyPairGenerator.getInstance("XDH") // May require specific provider or Android version
            // For X25519, specific parameter spec might be needed if not implicitly supported.
            // If using JDK 11+ style: kpg.initialize(NamedParameterSpec("X25519"))
            // Android might have its own ways or rely on Conscrypt/AndroidKeyStore for this.
            // This is a simplified example; direct X25519 might need BouncyCastle or manual setup.
            // As a fallback or for broader compatibility, BouncyCastle is recommended.
            // For now, let's assume a generic EC for placeholder purposes if "XDH" is not found.
            // val kpg = KeyPairGenerator.getInstance("EC")
            // kpg.initialize(255, SecureRandom()) // This is NOT X25519, just a placeholder

            // Placeholder until BouncyCastle is confirmed for X25519/Ed25519
            // This will likely fail or not produce correct X25519 keys with default providers.
            Log.w(TAG, "generateX25519KeyPair: Using placeholder. BouncyCastle recommended for X25519.")
            // Let's simulate failure for now to highlight the need for BouncyCastle or proper setup
             null // Replace with actual implementation using BouncyCastle or a compatible JCE provider
        } catch (e: Exception) {
            Log.e(TAG, "Error generating X25519 key pair: ${e.message}", e)
            null
        }
    }

    // For Ed25519 (Signatures)
    fun generateEd25519KeyPair(): KeyPair? {
         return try {
            // val kpg = KeyPairGenerator.getInstance("EdDSA", "BC") // With BouncyCastle
            // kpg.initialize(EdDSAParameterSpec("Ed25519"), SecureRandom())
            val kpg = KeyPairGenerator.getInstance("EdDSA") // Requires provider supporting EdDSA (e.g., BouncyCastle, Conscrypt on newer Android)
            // Similar to X25519, direct Ed25519 might need BouncyCastle for broader compatibility.
            Log.w(TAG, "generateEd25519KeyPair: Using placeholder. BouncyCastle recommended for Ed25519.")
            null // Replace with actual implementation
        } catch (e: Exception) {
            Log.e(TAG, "Error generating Ed25519 key pair: ${e.message}", e)
            null
        }
    }


    // --- Key Agreement (X25519) ---
    fun performKeyAgreement(privateKey: PrivateKey, publicKey: PublicKey): ByteArray? {
        return try {
            // val ka = KeyAgreement.getInstance("XDH", "BC") // With BouncyCastle
            val ka = KeyAgreement.getInstance("XDH") // Or specific algorithm like "X25519" if provider supports it
            ka.init(privateKey)
            ka.doPhase(publicKey, true)
            ka.generateSecret()
        } catch (e: Exception) {
            Log.e(TAG, "Error performing key agreement: ${e.message}", e)
            null
        }
    }

    // --- HKDF (HMAC-based Key Derivation Function) ---
    // Derives a key of desired length from the input key material (IKM)
    // salt and info are optional but recommended for security.
    fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray?, outputLengthBytes: Int): ByteArray? {
        return try {
            val prkMac = Mac.getInstance(HKDF_ALGORITHM)
            val actualSalt = salt ?: ByteArray(prkMac.macLength) // Zero-filled salt if null
            prkMac.init(SecretKeySpec(actualSalt, HKDF_ALGORITHM))
            val prk = prkMac.doFinal(ikm) // Pseudo-random key

            val result = ByteArray(outputLengthBytes)
            var bytesRemaining = outputLengthBytes
            var currentOffset = 0
            var t = ByteArray(0)
            var i = 1

            while (bytesRemaining > 0) {
                val okmMac = Mac.getInstance(HKDF_ALGORITHM)
                okmMac.init(SecretKeySpec(prk, HKDF_ALGORITHM))
                okmMac.update(t)
                if (info != null) {
                    okmMac.update(info)
                }
                okmMac.update(i.toByte())

                t = okmMac.doFinal()

                val copyLength = minOf(bytesRemaining, t.size)
                System.arraycopy(t, 0, result, currentOffset, copyLength)

                currentOffset += copyLength
                bytesRemaining -= copyLength
                i++
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Error performing HKDF: ${e.message}", e)
            null
        }
    }

    // --- AES-GCM Encryption ---
    fun encryptAES_GCM(plaintext: ByteArray, key: SecretKey, aad: ByteArray?): Pair<ByteArray, ByteArray>? { // Returns Pair(iv, ciphertext)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(GCM_IV_LENGTH)
            SecureRandom().nextBytes(iv) // Generate random IV
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec)
            if (aad != null) {
                cipher.updateAAD(aad)
            }
            val ciphertext = cipher.doFinal(plaintext)
            Pair(iv, ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "AES-GCM Encryption error: ${e.message}", e)
            null
        }
    }

    // --- AES-GCM Decryption ---
    fun decryptAES_GCM(ciphertextWithTag: ByteArray, key: SecretKey, iv: ByteArray, aad: ByteArray?): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

            cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec)
            if (aad != null) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(ciphertextWithTag)
        } catch (e: Exception) {
            Log.e(TAG, "AES-GCM Decryption error: ${e.message}", e)
            null
        }
    }

    // --- Ed25519 Signatures ---
    fun signEd25519(data: ByteArray, privateKey: PrivateKey): ByteArray? {
        return try {
            // val signature = Signature.getInstance("Ed25519", "BC") // With BouncyCastle
            val signature = Signature.getInstance("Ed25519") // Requires provider
            signature.initSign(privateKey)
            signature.update(data)
            signature.sign()
        } catch (e: Exception) {
            Log.e(TAG, "Error signing Ed25519 data: ${e.message}", e)
            null
        }
    }

    fun verifyEd25519(data: ByteArray, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            // val signature = Signature.getInstance("Ed25519", "BC") // With BouncyCastle
            val signature = Signature.getInstance("Ed25519") // Requires provider
            signature.initVerify(publicKey)
            signature.update(data)
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying Ed25519 signature: ${e.message}", e)
            false
        }
    }

    // --- PBKDF2 for Channel Passwords ---
    fun deriveKeyFromPassword(password: CharArray, salt: ByteArray): SecretKey? {
        return try {
            val factory = SecretKeyFactory.getInstance(PBE_ALGORITHM)
            val spec: KeySpec = PBEKeySpec(password, salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH)
            val tmp = factory.generateSecret(spec)
            SecretKeySpec(tmp.encoded, "AES") // Return as AES key
        } catch (e: Exception) {
            Log.e(TAG, "Error deriving key from password: ${e.message}", e)
            null
        }
    }

    // --- Key Conversion Utilities (Example for EC keys, may need adjustment for X25519/Ed25519) ---
    fun getPublicKeyFromBytes(keyBytes: ByteArray, algorithm: String = "EC"): PublicKey? {
        // For X25519/Ed25519, algorithm might be "XDH" or "EdDSA" respectively.
        // The KeyFactory provider must support these.
        return try {
            val keyFactory = KeyFactory.getInstance(algorithm) // Or "XDH", "EdDSA"
            val keySpec = X509EncodedKeySpec(keyBytes)
            keyFactory.generatePublic(keySpec)
        } catch (e: Exception) {
            Log.e(TAG, "Error converting bytes to PublicKey ($algorithm): ${e.message}", e)
            null
        }
    }

    fun getPrivateKeyFromBytes(keyBytes: ByteArray, algorithm: String = "EC"): PrivateKey? {
        return try {
            val keyFactory = KeyFactory.getInstance(algorithm) // Or "XDH", "EdDSA"
            val keySpec = PKCS8EncodedKeySpec(keyBytes)
            keyFactory.generatePrivate(keySpec)
        } catch (e: Exception) {
            Log.e(TAG, "Error converting bytes to PrivateKey ($algorithm): ${e.message}", e)
            null
        }
    }
}
