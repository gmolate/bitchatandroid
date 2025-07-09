package com.example.bitchat.services

import android.util.Log
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.spec.KeySpec
import java.util.Locale

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters


class EncryptionService {

    companion object {
        private const val TAG = "BitChatEncrypt" // Consistent TAG prefix
        const val AES_KEY_SIZE_BITS = 256
        const val GCM_IV_LENGTH_BYTES = 12
        const val GCM_TAG_LENGTH_BYTES = 16

        private const val HKDF_HMAC_ALGORITHM = "HmacSHA256" // Standard JCE name for HmacSHA256
        private const val PBE_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val PBE_ITERATION_COUNT = 65536
        private const val PBE_KEY_LENGTH_BITS = 256 // For deriving an AES-256 key

        const val BC_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME
        const val BC_ALGORITHM_X25519 = "X25519"
        const val BC_ALGORITHM_ED25519 = "Ed25519"

        init {
            if (Security.getProvider(BC_PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
                Log.i(TAG, "BouncyCastle security provider registered at position 1.")
            } else {
                Log.d(TAG, "BouncyCastle security provider already present.")
            }
        }
    }

    fun generateX25519KeyPair(): KeyPair? {
        Log.d(TAG, "Attempting to generate X25519 key pair using BouncyCastle...")
        return try {
            val kpg = KeyPairGenerator.getInstance(BC_ALGORITHM_X25519, BC_PROVIDER_NAME)
            // kpg.initialize(SecureRandom()) // For X25519, specific params often not needed with BC
            val keyPair = kpg.generateKeyPair()
            Log.i(TAG, "X25519 KeyPair generated successfully. PubKey Algo: ${keyPair.public.algorithm}, Format: ${keyPair.public.format}. PrivKey Algo: ${keyPair.private.algorithm}, Format: ${keyPair.private.format}")
            keyPair
        } catch (e: Exception) {
            Log.e(TAG, "Error generating X25519 key pair: ${e.message}", e)
            null
        }
    }

    fun generateEd25519KeyPair(): KeyPair? {
        Log.d(TAG, "Attempting to generate Ed25519 key pair using BouncyCastle...")
         return try {
            val kpg = KeyPairGenerator.getInstance(BC_ALGORITHM_ED25519, BC_PROVIDER_NAME)
            // kpg.initialize(SecureRandom()) // For Ed25519, specific params often not needed with BC
            val keyPair = kpg.generateKeyPair()
            Log.i(TAG, "Ed25519 KeyPair generated successfully. PubKey Algo: ${keyPair.public.algorithm}, Format: ${keyPair.public.format}. PrivKey Algo: ${keyPair.private.algorithm}, Format: ${keyPair.private.format}")
            keyPair
        } catch (e: Exception) {
            Log.e(TAG, "Error generating Ed25519 key pair: ${e.message}", e)
            null
        }
    }

    fun performKeyAgreement(privateKey: PrivateKey, publicKey: PublicKey): ByteArray? {
        Log.d(TAG, "Performing X25519 key agreement. PrivKey Algo: ${privateKey.algorithm}, PubKey Algo: ${publicKey.algorithm}")
        return try {
            val ka = KeyAgreement.getInstance(BC_ALGORITHM_X25519, BC_PROVIDER_NAME)
            ka.init(privateKey)
            ka.doPhase(publicKey, true)
            val sharedSecret = ka.generateSecret()
            Log.i(TAG, "X25519 key agreement successful. Shared secret length: ${sharedSecret.size} bytes.")
            sharedSecret
        } catch (e: Exception) {
            Log.e(TAG, "Error performing X25519 key agreement: ${e.message}", e)
            null
        }
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray?, outputLengthBytes: Int): ByteArray? {
        Log.d(TAG, "Performing HKDF. IKM size: ${ikm.size}, Salt size: ${salt?.size ?: "N/A"}, Info size: ${info?.size ?: "N/A"}, Output length: $outputLengthBytes bytes.")
        return try {
            // Using BouncyCastle's HKDFBytesGenerator for robust HKDF implementation
            val hkdf = HKDFBytesGenerator(SHA256Digest()) // Using SHA256 for HMAC in HKDF
            val effectiveSalt = salt ?: ByteArray(0) // BC HKDF handles null salt as empty salt
            val effectiveInfo = info ?: ByteArray(0)
            hkdf.init(HKDFParameters(ikm, effectiveSalt, effectiveInfo))
            val okm = ByteArray(outputLengthBytes) // Output Keying Material
            hkdf.generateBytes(okm, 0, outputLengthBytes)
            Log.i(TAG, "HKDF successful. Derived key material length: ${okm.size} bytes.")
            okm
        } catch (e: Exception) {
            Log.e(TAG, "Error performing HKDF: ${e.message}", e)
            null
        }
    }

    fun encryptAES_GCM(plaintext: ByteArray, key: SecretKey, aad: ByteArray?): Pair<ByteArray, ByteArray>? {
        Log.d(TAG, "Encrypting ${plaintext.size} bytes with AES-GCM. Key Algo: ${key.algorithm} (${key.encoded.size*8}-bit), AAD size: ${aad?.size ?: 0}B")
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(GCM_IV_LENGTH_BYTES)
            SecureRandom().nextBytes(iv)
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH_BYTES * 8, iv)

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec)
            aad?.let { cipher.updateAAD(it); Log.d(TAG, "AES-GCM Encryption: AAD updated (${it.size}B).") }
            val ciphertext = cipher.doFinal(plaintext)
            Log.i(TAG, "AES-GCM encryption successful. IV: ${iv.size}B, Ciphertext+Tag: ${ciphertext.size}B.")
            Pair(iv, ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "AES-GCM Encryption error: ${e.message}", e)
            null
        }
    }

    fun decryptAES_GCM(ciphertextWithTag: ByteArray, key: SecretKey, iv: ByteArray, aad: ByteArray?): ByteArray? {
        Log.d(TAG, "Decrypting ${ciphertextWithTag.size} bytes with AES-GCM. Key Algo: ${key.algorithm}, IV: ${iv.size}B, AAD size: ${aad?.size ?: 0}B")
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmParamSpec = GCMParameterSpec(GCM_TAG_LENGTH_BYTES * 8, iv)

            cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec)
            aad?.let { cipher.updateAAD(it); Log.d(TAG, "AES-GCM Decryption: AAD updated (${it.size}B).") }
            val plaintext = cipher.doFinal(ciphertextWithTag)
            Log.i(TAG, "AES-GCM decryption successful. Plaintext size: ${plaintext.size}B.")
            plaintext
        } catch (e: AEADBadTagException) {
            Log.w(TAG, "AES-GCM Decryption FAILED: AEADBadTagException (tag mismatch). Ciphertext size: ${ciphertextWithTag.size}B", e)
            null
        } catch (e: Exception) {
            Log.e(TAG, "AES-GCM Decryption error: ${e.message}. Ciphertext size: ${ciphertextWithTag.size}B", e)
            null
        }
    }

    fun signEd25519(data: ByteArray, privateKey: PrivateKey): ByteArray? {
        Log.d(TAG, "Signing ${data.size} bytes with Ed25519. PrivKey Algo: ${privateKey.algorithm}")
        return try {
            val signature = Signature.getInstance(BC_ALGORITHM_ED25519, BC_PROVIDER_NAME)
            signature.initSign(privateKey)
            signature.update(data)
            val sigBytes = signature.sign()
            Log.i(TAG, "Data (${data.size}B) signed with Ed25519. Signature length: ${sigBytes.size}B.")
            sigBytes
        } catch (e: Exception) {
            Log.e(TAG, "Error signing Ed25519 data: ${e.message}", e)
            null
        }
    }

    fun verifyEd25519(data: ByteArray, signatureBytes: ByteArray, publicKey: PublicKey): Boolean {
        Log.d(TAG, "Verifying Ed25519 signature (${signatureBytes.size}B) for data (${data.size}B). PubKey Algo: ${publicKey.algorithm}")
        return try {
            val signature = Signature.getInstance(BC_ALGORITHM_ED25519, BC_PROVIDER_NAME)
            signature.initVerify(publicKey)
            signature.update(data)
            val isValid = signature.verify(signatureBytes)
            Log.i(TAG, "Ed25519 signature verification result: $isValid for data size ${data.size}B.")
            isValid
        } catch (e: SignatureException) {
            Log.w(TAG, "Ed25519 signature verification FAILED (format/content invalid): ${e.message}")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying Ed25519 signature: ${e.message}", e)
            false
        }
    }

    fun deriveKeyFromPassword(password: CharArray, salt: ByteArray): SecretKey? {
        Log.d(TAG, "Deriving key from password using PBKDF2. Salt size: ${salt.size}B, Iterations: $PBE_ITERATION_COUNT, KeyLength: $PBE_KEY_LENGTH_BITS bits")
        return try {
            val factory = SecretKeyFactory.getInstance(PBE_ALGORITHM)
            val spec: KeySpec = PBEKeySpec(password, salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH_BITS)
            val tmp = factory.generateSecret(spec)
            val aesKey = SecretKeySpec(tmp.encoded, "AES")
            Log.i(TAG, "PBKDF2 key derivation successful. Derived AES key length: ${aesKey.encoded.size * 8} bits.")
            aesKey
        } catch (e: Exception) {
            Log.e(TAG, "Error deriving key from password using PBKDF2: ${e.message}", e)
            null
        }
    }

    private fun getKeyFromBytes(keyBytes: ByteArray, algorithm: String, isPublic: Boolean): Key? {
        val keyTypeStr = if (isPublic) "PublicKey" else "PrivateKey"
        Log.d(TAG, "Attempting to reconstruct $keyTypeStr from ${keyBytes.size} bytes using algorithm hint '$algorithm'.")

        val keyFactoryAlgorithm = when(algorithm.uppercase(Locale.ROOT)) {
            "EDDSA", BC_ALGORITHM_ED25519 -> BC_ALGORITHM_ED25519
            "XDH", BC_ALGORITHM_X25519 -> BC_ALGORITHM_X25519
            else -> algorithm
        }
        val keySpec = if (isPublic) X509EncodedKeySpec(keyBytes) else PKCS8EncodedKeySpec(keyBytes)

        try {
            Log.d(TAG, "Trying KeyFactory with algorithm '$keyFactoryAlgorithm' and provider '$BC_PROVIDER_NAME'.")
            val keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm, BC_PROVIDER_NAME)
            val key = if (isPublic) keyFactory.generatePublic(keySpec) else keyFactory.generatePrivate(keySpec)
            Log.i(TAG, "$keyTypeStr reconstructed successfully with BC Provider. Algo: ${key.algorithm}, Format: ${key.format}")
            return key
        } catch (e: Exception) {
            Log.w(TAG,"Failed to convert key bytes with BouncyCastle for algorithm $keyFactoryAlgorithm (Original hint: $algorithm). Error: ${e.message}. Trying default JCE provider with original hint '$algorithm'.")
            try {
                val keyFactory = KeyFactory.getInstance(algorithm) // Use original algorithm string for default provider
                val key = if (isPublic) keyFactory.generatePublic(keySpec) else keyFactory.generatePrivate(keySpec)
                Log.i(TAG, "$keyTypeStr reconstructed successfully with default JCE Provider. Algo: ${key.algorithm}, Format: ${key.format}")
                return key
            } catch (e2: Exception) {
                Log.e(TAG, "Error converting bytes to $keyTypeStr (Algo hint: $algorithm / Factory attempt: $keyFactoryAlgorithm) with both BC and default JCE: ${e2.message}", e2)
                return null
            }
        }
    }

    fun getPublicKeyFromBytes(keyBytes: ByteArray, algorithm: String = "EC"): PublicKey? {
        // For Ed25519, algorithm hint should be BC_ALGORITHM_ED25519 or "EdDSA"
        // For X25519, algorithm hint should be BC_ALGORITHM_X25519 or "XDH"
        return getKeyFromBytes(keyBytes, algorithm, true) as? PublicKey
    }

    fun getPrivateKeyFromBytes(keyBytes: ByteArray, algorithm: String = "EC"): PrivateKey? {
       return getKeyFromBytes(keyBytes, algorithm, false) as? PrivateKey
    }
}
