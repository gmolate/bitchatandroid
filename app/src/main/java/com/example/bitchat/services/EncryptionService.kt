package com.example.bitchat.services

import android.security.keystore.KeyProperties
import android.util.Log
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.Security
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
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.util.Locale // For uppercase in key conversion

// Import BouncyCastle provider and specific specs
import org.bouncycastle.jce.provider.BouncyCastleProvider
// It's good practice to use the specific specs if available and clear
// import org.bouncycastle.jcajce.spec.EdDSAParameterSpec
// import org.bouncycastle.jcajce.spec.XDHParameterSpec


/**
 * Handles cryptographic operations for the BitChat application.
 * This includes key generation, key agreement, encryption/decryption,
 * digital signatures, and password-based key derivation.
 *
 * Uses BouncyCastle for Ed25519 and X25519 operations for reliability and consistency.
 */
class EncryptionService {

    companion object {
        private const val TAG = "EncryptionService"
        const val AES_KEY_SIZE = 256 // bits
        const val GCM_IV_LENGTH = 12 // bytes (96 bits is recommended for GCM)
        const val GCM_TAG_LENGTH = 16 // bytes (128 bits is standard for AES-GCM)

        private const val HKDF_ALGORITHM = "HmacSHA256" // Algorithm for HKDF's HMAC
        private const val PBE_ALGORITHM = "PBKDF2WithHmacSHA256" // Algorithm for password-based key derivation
        private const val PBE_ITERATION_COUNT = 65536 // Standard iteration count, should match iOS
        private const val PBE_KEY_LENGTH = 256 // bits, for deriving an AES-256 key

        // BouncyCastle specific names for algorithms
        private const val BC_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME // Standard name "BC"
        const val BC_ALGORITHM_X25519 = "X25519" // For KeyPairGenerator and KeyAgreement with BouncyCastle
        const val BC_ALGORITHM_ED25519 = "Ed25519" // For KeyPairGenerator and Signature with BouncyCastle

        init {
            // Ensure BouncyCastle is added as a security provider if not already present.
            // This is crucial for reliable Ed25519 and X25519 support.
            if (Security.getProvider(BC_PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1) // Insert at position 1 for preference
                Log.i(TAG, "BouncyCastle security provider added successfully.")
            } else {
                Log.d(TAG, "BouncyCastle security provider already present.")
            }
        }
    }

    // --- Key Pair Generation ---

    /**
     * Generates an X25519 key pair for Diffie-Hellman key agreement using BouncyCastle.
     * X25519 is a specific type of Elliptic Curve Diffie-Hellman (ECDH) key agreement.
     * @return A KeyPair for X25519, or null on failure.
     */
    fun generateX25519KeyPair(): KeyPair? {
        return try {
            val kpg = KeyPairGenerator.getInstance(BC_ALGORITHM_X25519, BC_PROVIDER_NAME)
            // For X25519 with BouncyCastle, initializing with just SecureRandom is generally sufficient
            // as the "X25519" algorithm string implies the specific curve parameters.
            kpg.initialize(SecureRandom())
            kpg.generateKeyPair().also {
                Log.d(TAG, "X25519 KeyPair generated. Public key format: ${it.public.format}, Algorithm: ${it.public.algorithm}")
            }
        } catch (e: NoSuchAlgorithmException) {
            Log.e(TAG, "NoSuchAlgorithmException for X25519 with BouncyCastle. Provider issue? ${e.message}", e)
            null
        } catch (e: InvalidAlgorithmParameterException) { // Should not happen with SecureRandom only for named curve
             Log.e(TAG, "InvalidAlgorithmParameterException for X25519 with BouncyCastle. ${e.message}", e)
            null
        }
        catch (e: Exception) { // Catch any other unexpected errors
            Log.e(TAG, "Error generating X25519 key pair using BouncyCastle: ${e.message}", e)
            null
        }
    }

    /**
     * Generates an Ed25519 key pair for digital signatures using BouncyCastle.
     * Ed25519 is a specific type of Edwards-curve Digital Signature Algorithm (EdDSA).
     * @return A KeyPair for Ed25519, or null on failure.
     */
    fun generateEd25519KeyPair(): KeyPair? {
         return try {
            val kpg = KeyPairGenerator.getInstance(BC_ALGORITHM_ED25519, BC_PROVIDER_NAME)
            // For Ed25519 with BouncyCastle, initializing with just SecureRandom is generally sufficient.
            kpg.initialize(SecureRandom())
            kpg.generateKeyPair().also {
                 Log.d(TAG, "Ed25519 KeyPair generated. Public key format: ${it.public.format}, Algorithm: ${it.public.algorithm}")
            }
        } catch (e: NoSuchAlgorithmException) {
            Log.e(TAG, "NoSuchAlgorithmException for Ed25519 with BouncyCastle. Provider issue? ${e.message}", e)
            null
        } catch (e: InvalidAlgorithmParameterException) { // Should not happen with SecureRandom only for named curve
             Log.e(TAG, "InvalidAlgorithmParameterException for Ed25519 with BouncyCastle. ${e.message}", e)
            null
        }
        catch (e: Exception) {
            Log.e(TAG, "Error generating Ed25519 key pair using BouncyCastle: ${e.message}", e)
            null
        }
    }


    // --- Key Agreement (X25519) ---
    /**
     * Performs X25519 key agreement to establish a shared secret using BouncyCastle.
     * @param privateKey The local private X25519 key.
     * @param publicKey The remote public X25519 key.
     * @return The shared secret as a byte array (typically 32 bytes for X25519), or null on failure.
     */
    fun performKeyAgreement(privateKey: PrivateKey, publicKey: PublicKey): ByteArray? {
        return try {
            val ka = KeyAgreement.getInstance(BC_ALGORITHM_X25519, BC_PROVIDER_NAME)
            ka.init(privateKey)
            ka.doPhase(publicKey, true) // true indicates this is the last phase for this key agreement
            ka.generateSecret()
        } catch (e: InvalidKeyException) {
            Log.e(TAG, "Invalid key for X25519 key agreement (BouncyCastle): ${e.message}", e)
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error performing X25519 key agreement (BouncyCastle): ${e.message}", e)
            null
        }
    }

    // --- HKDF (HMAC-based Key Derivation Function as per RFC 5869) ---
    /**
     * Derives a key of a specified length from Input Keying Material (IKM) using HKDF with HMAC-SHA256.
     * @param ikm Input Keying Material (e.g., shared secret from X25519).
     * @param salt Optional salt value. If null, a salt of all zeros of hash length is used (as per RFC 5869).
     * @param info Optional context and application-specific information (can be null or empty).
     * @param outputLengthBytes The desired length of the output key in bytes.
     * @return The derived key as a byte array, or null on failure.
     */
    fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray?, outputLengthBytes: Int): ByteArray? {
        try {
            val prkMac = Mac.getInstance(HKDF_ALGORITHM) // Standard JCE provider for HmacSHA256 should be fine
            val actualSalt = salt ?: ByteArray(prkMac.macLength) // If salt is null, use a zero-filled byte array of HmacSHA256 output length
            prkMac.init(SecretKeySpec(actualSalt, HKDF_ALGORITHM))
            val prk = prkMac.doFinal(ikm) // Step 1: Extract - Pseudo-Random Key (PRK)

            // Step 2: Expand
            val result = ByteArray(outputLengthBytes)
            var bytesRemaining = outputLengthBytes
            var currentOffset = 0
            var t = ByteArray(0) // T(0) is an empty string for the first iteration
            var i = 1 // Counter for iterations

            while (bytesRemaining > 0) {
                val okmMac = Mac.getInstance(HKDF_ALGORITHM)
                okmMac.init(SecretKeySpec(prk, HKDF_ALGORITHM))
                okmMac.update(t) // T(i-1)
                if (info != null) {
                    okmMac.update(info) // Context/application-specific info
                }
                okmMac.update(i.toByte()) // Iteration counter (1-based)

                t = okmMac.doFinal() // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)

                val copyLength = minOf(bytesRemaining, t.size)
                System.arraycopy(t, 0, result, currentOffset, copyLength)

                currentOffset += copyLength
                bytesRemaining -= copyLength
                i++

                // RFC 5869: L (outputLengthBytes) must be <= 255 * HashLen.
                // For SHA-256 (HashLen=32), max L is 255*32 = 8160 bytes.
                // If i > 255, it implies an excessively long key was requested.
                if (i > 255) {
                    Log.e(TAG, "HKDF output length too large ($outputLengthBytes bytes), counter exceeded 255.")
                    return null
                }
            }
            return result
        } catch (e: Exception) {
            Log.e(TAG, "Error performing HKDF: ${e.message}", e)
            return null
        }
    }

    // --- AES-GCM Encryption ---
    /**
     * Encrypts plaintext using AES-GCM (AES-256-GCM with 12-byte IV and 16-byte tag).
     * @param plaintext The data to encrypt.
     * @param key The AES SecretKey (must be 256-bit for AES-256).
     * @param aad Optional Additional Authenticated Data (AAD) to include in authentication.
     * @return A Pair containing the IV (nonce) and the ciphertext (which includes the authentication tag), or null on failure.
     */
    fun encryptAES_GCM(plaintext: ByteArray, key: SecretKey, aad: ByteArray?): Pair<ByteArray, ByteArray>? {
        return try {
            // Using default JCE provider, which typically includes AES/GCM support (often via Conscrypt on Android)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(GCM_IV_LENGTH)
            SecureRandom().nextBytes(iv) // Generate a cryptographically strong random IV for each encryption
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv) // Tag length in bits (128 bits = 16 bytes)

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec)
            if (aad != null) {
                cipher.updateAAD(aad) // Include AAD in the authentication
            }
            val ciphertext = cipher.doFinal(plaintext) // Perform encryption and append authentication tag
            Pair(iv, ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "AES-GCM Encryption error: ${e.message}", e)
            null
        }
    }

    // --- AES-GCM Decryption ---
    /**
     * Decrypts ciphertext using AES-GCM.
     * @param ciphertextWithTag The ciphertext, which must include the authentication tag.
     * @param key The AES SecretKey.
     * @param iv The Initialization Vector (nonce) used for encryption.
     * @param aad Optional Additional Authenticated Data (AAD) used during encryption.
     * @return The decrypted plaintext as a byte array, or null if decryption or authentication tag verification fails.
     */
    fun decryptAES_GCM(ciphertextWithTag: ByteArray, key: SecretKey, iv: ByteArray, aad: ByteArray?): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

            cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec)
            if (aad != null) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(ciphertextWithTag)
        } catch (e: javax.crypto.AEADBadTagException) { // Specifically catch tag mismatch
            Log.w(TAG, "AES-GCM Decryption failed: AEADBadTagException (authentication tag mismatch). ${e.message}")
            null
        } catch (e: Exception) {
            Log.e(TAG, "AES-GCM Decryption error: ${e.message}", e)
            null
        }
    }

    // --- Ed25519 Signatures ---
    /**
     * Signs data using an Ed25519 private key with BouncyCastle.
     * @param data The data to sign.
     * @param privateKey The Ed25519 PrivateKey.
     * @return The signature as a byte array, or null on failure.
     */
    fun signEd25519(data: ByteArray, privateKey: PrivateKey): ByteArray? {
        return try {
            val signature = Signature.getInstance(BC_ALGORITHM_ED25519, BC_PROVIDER_NAME)
            signature.initSign(privateKey)
            signature.update(data)
            signature.sign()
        } catch (e: InvalidKeyException) {
            Log.e(TAG, "Invalid key for Ed25519 signing (BouncyCastle): ${e.message}", e)
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error signing Ed25519 data (BouncyCastle): ${e.message}", e)
            null
        }
    }

    /**
     * Verifies an Ed25519 signature with BouncyCastle.
     * @param data The original data that was signed.
     * @param signatureBytes The signature to verify.
     * @param publicKey The Ed25519 PublicKey.
     * @return True if the signature is valid, false otherwise.
     */
    fun verifyEd25519(data: ByteArray, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val signature = Signature.getInstance(BC_ALGORITHM_ED25519, BC_PROVIDER_NAME)
            signature.initVerify(publicKey)
            signature.update(data)
            signature.verify(signatureBytes)
        } catch (e: InvalidKeyException) {
            Log.e(TAG, "Invalid key for Ed25519 verification (BouncyCastle): ${e.message}", e)
            false
        } catch (e: SignatureException) { // Catch if signature bytes are malformed or verification itself fails
            Log.w(TAG, "Ed25519 signature verification failed (format or content - BouncyCastle): ${e.message}")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying Ed25519 signature (BouncyCastle): ${e.message}", e)
            false
        }
    }

    // --- PBKDF2 for Channel Passwords ---
    /**
     * Derives an AES key from a password and salt using PBKDF2WithHmacSHA256.
     * @param password The channel password.
     * @param salt A cryptographically random salt (should be unique per password/channel).
     * @return A SecretKey suitable for AES-256 (PBE_KEY_LENGTH bits), or null on failure.
     */
    fun deriveKeyFromPassword(password: CharArray, salt: ByteArray): SecretKey? {
        return try {
            val factory = SecretKeyFactory.getInstance(PBE_ALGORITHM)
            val spec: KeySpec = PBEKeySpec(password, salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH)
            val tmp = factory.generateSecret(spec)
            SecretKeySpec(tmp.encoded, "AES") // Return as an AES SecretKey
        } catch (e: Exception) {
            Log.e(TAG, "Error deriving key from password using PBKDF2: ${e.message}", e)
            null
        }
    }

    // --- Key Conversion Utilities ---

    /**
     * Converts a byte array (X.509 encoded for public, PKCS#8 for private) to a Key object.
     * Attempts to use BouncyCastle provider first for specified algorithms (EdDSA, XDH),
     * then falls back to default JCE provider if BC fails.
     * @param keyBytes The raw bytes of the key.
     * @param algorithm The key algorithm (e.g., "EC", "XDH", "EdDSA").
     * @param isPublic True if converting a public key, false for a private key.
     * @return The Key object, or null on failure.
     */
    private fun getKeyFromBytes(keyBytes: ByteArray, algorithm: String, isPublic: Boolean): Key? {
        // Determine the algorithm name to use with BouncyCastle, defaulting to original for other cases
        val keyFactoryAlgorithm = when(algorithm.uppercase(Locale.ROOT)) {
            "EDDSA", BC_ALGORITHM_ED25519 -> BC_ALGORITHM_ED25519 // Use BC's specific Ed25519 name
            "XDH", BC_ALGORITHM_X25519 -> BC_ALGORITHM_X25519     // Use BC's specific X25519 name
            else -> algorithm // For generic "EC" or other algorithms
        }
        val keySpec = if (isPublic) X509EncodedKeySpec(keyBytes) else PKCS8EncodedKeySpec(keyBytes)

        try {
            // Attempt with BouncyCastle provider first for the specified (or mapped) algorithm
            val keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, BC_PROVIDER_NAME)
            return if (isPublic) keyFactory.generatePublic(keySpec) else keyFactory.generatePrivate(keySpec)
        } catch (e: Exception) {
            // Log the BouncyCastle attempt failure and try with default JCE provider
            Log.w(TAG,"Failed to convert key bytes with BouncyCastle for algorithm $keyFactoryAlgorithm (Original: $algorithm). Error: ${e.message}. Trying default JCE provider.")
            try {
                // Use the original algorithm string for the default JCE provider
                val keyFactory = KeyFactory.getInstance(algorithm)
                return if (isPublic) keyFactory.generatePublic(keySpec) else keyFactory.generatePrivate(keySpec)
            } catch (e2: Exception) {
                Log.e(TAG, "Error converting bytes to ${if (isPublic) "PublicKey" else "PrivateKey"} (Algorithm: $algorithm / $keyFactoryAlgorithm) with both BC and default: ${e2.message}", e2)
                return null
            }
        }
    }

    /**
     * Converts a byte array (X.509 encoded) to a PublicKey.
     * Prioritizes BouncyCastle for known BC algorithms (Ed25519, X25519).
     * @param keyBytes The raw bytes of the public key.
     * @param algorithm The key algorithm (e.g., "EC", "XDH", "EdDSA"). Defaults to "EC".
     * @return The PublicKey object, or null on failure.
     */
    fun getPublicKeyFromBytes(keyBytes: ByteArray, algorithm: String = "EC"): PublicKey? {
        return getKeyFromBytes(keyBytes, algorithm, true) as? PublicKey
    }

    /**
     * Converts a byte array (PKCS#8 encoded) to a PrivateKey.
     * Prioritizes BouncyCastle for known BC algorithms (Ed25519, X25519).
     * @param keyBytes The raw bytes of the private key.
     * @param algorithm The key algorithm (e.g., "EC", "XDH", "EdDSA"). Defaults to "EC".
     * @return The PrivateKey object, or null on failure.
     */
    fun getPrivateKeyFromBytes(keyBytes: ByteArray, algorithm: String = "EC"): PrivateKey? {
       return getKeyFromBytes(keyBytes, algorithm, false) as? PrivateKey
    }
}

[end of app/src/main/java/com/example/bitchat/services/EncryptionService.kt]
