package com.example.bitchat.services

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
// Import BouncyCastle provider if you intend to use it directly in tests or if it's required for specific algorithms
// import org.bouncycastle.jce.provider.BouncyCastleProvider

class EncryptionServiceTest {

    private lateinit var encryptionService: EncryptionService

    @Before
    fun setUp() {
        // It's good practice to add BouncyCastle provider if you rely on it,
        // especially for consistent behavior across test environments.
        // if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        //     Security.addProvider(BouncyCastleProvider())
        // }
        encryptionService = EncryptionService()
    }

    @Test
    fun hkdf_derivesKeyOfCorrectLength() {
        val ikm = "InitialKeyMaterial".toByteArray()
        val salt = "SaltySalt".toByteArray()
        val info = "ContextInfo".toByteArray()
        val outputLength32Bytes = 32
        val outputLength16Bytes = 16

        val derivedKey32 = encryptionService.hkdf(ikm, salt, info, outputLength32Bytes)
        assertNotNull("Derived key (32 bytes) should not be null", derivedKey32)
        assertEquals("Derived key (32 bytes) should have the correct length", outputLength32Bytes, derivedKey32?.size)

        val derivedKey16 = encryptionService.hkdf(ikm, salt, info, outputLength16Bytes)
        assertNotNull("Derived key (16 bytes) should not be null", derivedKey16)
        assertEquals("Derived key (16 bytes) should have the correct length", outputLength16Bytes, derivedKey16?.size)

        // Test that different info produces different keys (basic check)
        val info2 = "DifferentContextInfo".toByteArray()
        val derivedKey32_info2 = encryptionService.hkdf(ikm, salt, info2, outputLength32Bytes)
        assertNotNull(derivedKey32_info2)
        assertFalse("Keys derived with different info should not be the same", derivedKey32.contentEquals(derivedKey32_info2!!))
    }

    @Test
    fun hkdf_nullSaltAndInfo_derivesKey() {
        val ikm = "AnotherKeyMaterial".toByteArray()
        val outputLength = 32
        val derivedKey = encryptionService.hkdf(ikm, null, null, outputLength)
        assertNotNull("Derived key with null salt/info should not be null", derivedKey)
        assertEquals("Derived key with null salt/info should have correct length", outputLength, derivedKey?.size)
    }

    @Test
    fun encryptDecryptAES_GCM_successful() {
        val plaintext = "This is a secret message for AES-GCM.".toByteArray()
        // Generate a dummy AES key for testing
        val keyBytes = ByteArray(256 / 8)
        SecureRandom().nextBytes(keyBytes)
        val aesKey: SecretKey = SecretKeySpec(keyBytes, "AES")
        val aad = "AdditionalAuthenticatedData".toByteArray()

        val encryptionResult = encryptionService.encryptAES_GCM(plaintext, aesKey, aad)
        assertNotNull("Encryption result should not be null", encryptionResult)
        val (iv, ciphertext) = encryptionResult!!
        assertNotNull("IV should not be null", iv)
        assertEquals("IV length should be correct", EncryptionService.Companion.GCM_IV_LENGTH, iv.size)
        assertNotNull("Ciphertext should not be null", ciphertext)
        // Ciphertext includes the tag, so it should be plaintext.size + GCM_TAG_LENGTH
        assertTrue("Ciphertext length seems incorrect", ciphertext.size >= plaintext.size)


        val decryptedText = encryptionService.decryptAES_GCM(ciphertext, aesKey, iv, aad)
        assertNotNull("Decryption result should not be null", decryptedText)
        assertArrayEquals("Decrypted text should match original plaintext", plaintext, decryptedText)
    }

    @Test
    fun encryptDecryptAES_GCM_noAad_successful() {
        val plaintext = "Secret message without AAD.".toByteArray()
        val keyBytes = ByteArray(256 / 8)
        SecureRandom().nextBytes(keyBytes)
        val aesKey: SecretKey = SecretKeySpec(keyBytes, "AES")

        val encryptionResult = encryptionService.encryptAES_GCM(plaintext, aesKey, null)
        assertNotNull(encryptionResult)
        val (iv, ciphertext) = encryptionResult!!

        val decryptedText = encryptionService.decryptAES_GCM(ciphertext, aesKey, iv, null)
        assertNotNull(decryptedText)
        assertArrayEquals(plaintext, decryptedText)
    }


    @Test
    fun decryptAES_GCM_tamperedCiphertext_fails() {
        val plaintext = "Another secret.".toByteArray()
        val keyBytes = ByteArray(256 / 8); SecureRandom().nextBytes(keyBytes)
        val aesKey: SecretKey = SecretKeySpec(keyBytes, "AES")

        val (iv, ciphertext) = encryptionService.encryptAES_GCM(plaintext, aesKey, null)!!

        // Tamper with ciphertext
        if (ciphertext.isNotEmpty()) {
            ciphertext[ciphertext.size / 2] = (ciphertext[ciphertext.size / 2] + 1).toByte()
        } else {
            // Cannot tamper if empty, but this case should ideally not occur for non-empty plaintext
            fail("Ciphertext was empty, cannot test tampering effect.")
        }

        val decryptedText = encryptionService.decryptAES_GCM(ciphertext, aesKey, iv, null)
        assertNull("Decryption of tampered ciphertext should fail (return null)", decryptedText)
    }

    @Test
    fun decryptAES_GCM_incorrectKey_fails() {
        val plaintext = "Secret with wrong key.".toByteArray()
        val keyBytes1 = ByteArray(256 / 8); SecureRandom().nextBytes(keyBytes1)
        val aesKey1: SecretKey = SecretKeySpec(keyBytes1, "AES")
        val keyBytes2 = ByteArray(256 / 8); SecureRandom().nextBytes(keyBytes2) // Different key
        val aesKey2: SecretKey = SecretKeySpec(keyBytes2, "AES")

        val (iv, ciphertext) = encryptionService.encryptAES_GCM(plaintext, aesKey1, null)!!
        val decryptedText = encryptionService.decryptAES_GCM(ciphertext, aesKey2, iv, null)
        assertNull("Decryption with incorrect key should fail", decryptedText)
    }

    @Test
    fun decryptAES_GCM_incorrectAad_fails() {
        val plaintext = "Secret with AAD.".toByteArray()
        val keyBytes = ByteArray(256 / 8); SecureRandom().nextBytes(keyBytes)
        val aesKey: SecretKey = SecretKeySpec(keyBytes, "AES")
        val aad1 = "AAD1".toByteArray()
        val aad2 = "AAD2".toByteArray()

        val (iv, ciphertext) = encryptionService.encryptAES_GCM(plaintext, aesKey, aad1)!!
        val decryptedText = encryptionService.decryptAES_GCM(ciphertext, aesKey, iv, aad2)
        assertNull("Decryption with incorrect AAD should fail", decryptedText)
    }

    @Test
    fun deriveKeyFromPassword_producesKey() {
        val password = "channelPassword123".toCharArray()
        val salt = ByteArray(16); SecureRandom().nextBytes(salt)

        val derivedKey = encryptionService.deriveKeyFromPassword(password, salt)
        assertNotNull("Derived key should not be null", derivedKey)
        assertEquals("Derived key should be AES type", "AES", derivedKey?.algorithm)
        assertEquals("Derived key length should be correct for AES-256", 256 / 8, derivedKey?.encoded?.size)
    }

    // --- Placeholder tests for X25519/Ed25519 ---
    // These will likely require BouncyCastle or a specific test setup with Android Keystore.
    // For now, they might just test that the methods return null or don't crash,
    // given the current placeholder nature of these functions in EncryptionService.

    @Test
    fun generateX25519KeyPair_placeholderBehavior() {
        // Current implementation returns null or might throw without proper provider
        // This test just checks it doesn't crash unexpectedly if it's a pure placeholder.
        // If BouncyCastle is integrated, this test would be more robust.
        val keyPair = encryptionService.generateX25519KeyPair()
        // Depending on placeholder:
        // assertNull("X25519 key pair generation is a placeholder, expected null or specific behavior", keyPair)
        // OR if it's expected to work with a default provider (less likely for X25519 without setup):
        // assertNotNull(keyPair)
        // assertEquals("XDH", keyPair.public.algorithm) // Or "X25519"
        assertTrue("Test needs to be adapted once X25519 generation is finalized", true)
    }

    @Test
    fun generateEd25519KeyPair_placeholderBehavior() {
        val keyPair = encryptionService.generateEd25519KeyPair()
        // Similar to X25519, adapt based on actual implementation status
        assertTrue("Test needs to be adapted once Ed25519 generation is finalized", true)
    }

    // More tests would be needed for key agreement, signing, and verification
    // once X25519/Ed25519 are fully implemented (likely with BouncyCastle).
}
