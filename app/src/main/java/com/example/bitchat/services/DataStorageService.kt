package com.example.bitchat.services

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit as dsEdit // Alias for DataStore edit, to avoid conflict with SharedPreferences.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// Create a DataStore instance at the top level of your Kotlin file.
val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "bitchat_settings")

class DataStorageService(private val context: Context) {

    companion object {
        private const val TAG = "DataStorageService"

        // SharedPreferences (Legacy, can be replaced entirely by DataStore)
        private const val PREFS_NAME = "bitchat_shared_prefs"
        private const val KEY_DISPLAY_NAME = "display_name"

        // DataStore Keys
        val DISPLAY_NAME_DS_KEY = stringPreferencesKey("display_name_ds")
        val USER_EPHEMERAL_ID_DS_KEY = stringPreferencesKey("user_ephemeral_id_ds")
        // Add other DataStore keys as needed

        // Android Keystore Alias
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val IDENTITY_KEY_ALIAS = "BitChat_UserIdentityKey" // For Ed25519 persistent key
        private const val CHANNEL_PASSWORD_KEY_ALIAS_PREFIX = "BitChat_ChannelKey_" // For AES keys derived from channel passwords

        // Keystore Cipher Transformation for symmetric keys (used for channel passwords)
        // Note: Android Keystore encryption for arbitrary data is more complex than just storing a raw key.
        // It often involves generating a key in Keystore, then using that key to encrypt/decrypt data.
        // For storing channel passwords, we might store an *encrypted version* of a hash, or a derived key.
        // For simplicity here, we'll show storing an AES key used to encrypt the password hash itself,
        // or directly storing a key derived from PBKDF2 and protected by Keystore.
        private const val KEYSTORE_AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEYSTORE_IV_SEPARATOR = "_IV_"
    }

    // --- Display Name (using DataStore) ---
    val displayNameFlow: Flow<String?> = context.dataStore.data
        .map { preferences ->
            preferences[DISPLAY_NAME_DS_KEY]
        }

    suspend fun saveDisplayName(displayName: String) {
        context.dataStore.dsEdit { settings ->
            settings[DISPLAY_NAME_DS_KEY] = displayName
        }
        Log.d(TAG, "Display name saved to DataStore.")
    }

    // --- User Ephemeral ID (using DataStore, example) ---
     val userEphemeralIdFlow: Flow<String?> = context.dataStore.data
        .map { preferences ->
            preferences[USER_EPHEMERAL_ID_DS_KEY]
        }
    suspend fun saveUserEphemeralId(ephemeralId: String) {
        context.dataStore.dsEdit { settings ->
            settings[USER_EPHEMERAL_ID_DS_KEY] = ephemeralId
        }
        Log.d(TAG, "User ephemeral ID saved to DataStore.")
    }
    suspend fun getUserEphemeralId(): String? {
        return userEphemeralIdFlow.firstOrNull()
    }


    // --- Persistent Identity Key (Ed25519 using Android Keystore) ---

    fun getOrGenerateIdentityKeyPair(): KeyPair? {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)

            val privateKey = keyStore.getKey(IDENTITY_KEY_ALIAS, null) as? PrivateKey
            val publicKey = keyStore.getCertificate(IDENTITY_KEY_ALIAS)?.publicKey

            if (privateKey != null && publicKey != null) {
                Log.d(TAG, "Identity key pair loaded from Keystore.")
                return KeyPair(publicKey, privateKey)
            } else {
                Log.d(TAG, "Identity key pair not found in Keystore, generating new one.")
                // For Ed25519, KeyPairGenerator might need BouncyCastle or specific Android version
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE_PROVIDER)
                val parameterSpec = KeyGenParameterSpec.Builder(
                    IDENTITY_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                ).run {
                    // For Ed25519, a specific curve name or size might be needed.
                    // KeyProperties.KEY_ALGORITHM_EC with an EdDSA signature scheme implies an EdDSA-compatible curve.
                    // Android P (API 28) added support for Ed25519.
                    // If using BouncyCastle to generate, you'd import it differently.
                    // This example relies on Android Keystore's EC capabilities which should support Ed25519 on API 28+.
                    // setAlgorithmParameterSpec(ECGenParameterSpec("ed25519")) // This might be needed with some JCE setups
                    setDigests(KeyProperties.DIGEST_NONE) // EdDSA typically includes the hash
                    // No setKeySize for Ed25519 as it's fixed.
                    build()
                }
                kpg.initialize(parameterSpec)
                val kp = kpg.generateKeyPair()
                Log.d(TAG, "New identity key pair generated and stored in Keystore.")
                return kp
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error accessing or generating identity key pair: ${e.message}", e)
            return null
        }
    }

    fun getIdentityPublicKey(): PublicKey? {
         try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)
            return keyStore.getCertificate(IDENTITY_KEY_ALIAS)?.publicKey
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving identity public key: ${e.message}", e)
            return null
        }
    }
     fun getIdentityPrivateKey(): PrivateKey? {
         try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)
            return keyStore.getKey(IDENTITY_KEY_ALIAS, null) as? PrivateKey
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving identity private key: ${e.message}", e)
            return null
        }
    }


    // --- Channel Password Derived Key Storage (AES key in Keystore) ---
    // This is a simplified example. In a real app, you'd use the derived key from PBKDF2
    // and potentially encrypt that derived key with a Keystore master key, or store the
    // PBKDF2 parameters and re-derive as needed, only storing the salt.
    // For simplicity, we'll simulate storing a key directly if Keystore allowed it,
    // or more practically, generating an AES key in Keystore to encrypt the *actual* channel key.

    /**
     * Stores an AES key (e.g., derived from a channel password via PBKDF2)
     * by encrypting it with a master key in Android Keystore.
     * This is more secure than storing the raw key directly in SharedPreferences.
     */
    fun saveChannelKey(channelName: String, keyToProtect: SecretKey): Boolean {
        val alias = CHANNEL_PASSWORD_KEY_ALIAS_PREFIX + channelName.hashCode().toString()
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)

            // Generate a wrapping key in Keystore if it doesn't exist
            if (!keyStore.containsAlias(alias)) {
                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEYSTORE_PROVIDER
                )
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGenerator.init(spec)
                keyGenerator.generateKey() // This key stays in Keystore
            }

            val keystoreKey = keyStore.getKey(alias, null) as SecretKey

            val cipher = Cipher.getInstance(KEYSTORE_AES_GCM_TRANSFORMATION) // Provider might be specified for GCM
            cipher.init(Cipher.ENCRYPT_MODE, keystoreKey) // IV is generated by Cipher

            val encryptedKey = cipher.doFinal(keyToProtect.encoded)
            val iv = cipher.iv

            // Store encrypted key and IV in SharedPreferences or DataStore
            context.dataStore.dsEdit { settings ->
                settings[stringPreferencesKey("enc_channel_key_$channelName")] = android.util.Base64.encodeToString(encryptedKey, android.util.Base64.NO_WRAP)
                settings[stringPreferencesKey("enc_channel_iv_$channelName")] = android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP)
            }
            Log.d(TAG, "Channel key for '$channelName' encrypted and stored.")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error saving channel key for '$channelName': ${e.message}", e)
            return false
        }
    }

    /**
     * Retrieves a channel-specific AES key, decrypting it using the master key from Android Keystore.
     */
    suspend fun getChannelKey(channelName: String): SecretKey? {
        val alias = CHANNEL_PASSWORD_KEY_ALIAS_PREFIX + channelName.hashCode().toString()
        try {
            val preferences = context.dataStore.data.firstOrNull() ?: return null
            val encryptedKeyB64 = preferences[stringPreferencesKey("enc_channel_key_$channelName")] ?: return null
            val ivB64 = preferences[stringPreferencesKey("enc_channel_iv_$channelName")] ?: return null

            val encryptedKey = android.util.Base64.decode(encryptedKeyB64, android.util.Base64.NO_WRAP)
            val iv = android.util.Base64.decode(ivB64, android.util.Base64.NO_WRAP)

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)

            if (!keyStore.containsAlias(alias)) {
                Log.w(TAG, "Keystore key for channel '$channelName' not found.")
                return null
            }
            val keystoreKey = keyStore.getKey(alias, null) as SecretKey

            val cipher = Cipher.getInstance(KEYSTORE_AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(128, iv) // Tag length 128 bits
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey, spec)

            val decryptedKeyBytes = cipher.doFinal(encryptedKey)
            Log.d(TAG, "Channel key for '$channelName' retrieved and decrypted.")
            return SecretKeySpec(decryptedKeyBytes, "AES")

        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving or decrypting channel key for '$channelName': ${e.message}", e)
            return null
        }
    }

    suspend fun deleteChannelKey(channelName: String) {
        val alias = CHANNEL_PASSWORD_KEY_ALIAS_PREFIX + channelName.hashCode().toString()
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
            context.dataStore.dsEdit { settings ->
                settings.remove(stringPreferencesKey("enc_channel_key_$channelName"))
                settings.remove(stringPreferencesKey("enc_channel_iv_$channelName"))
            }
            Log.d(TAG, "Channel key and Keystore entry for '$channelName' deleted.")
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting channel key for '$channelName': ${e.message}", e)
        }
    }


    // --- SharedPreferences (Legacy Example - can be removed if fully migrating to DataStore) ---
    @Deprecated("Use DataStore instead for display name")
    fun saveDisplayNameSharedPrefs(displayName: String) {
        val sharedPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        sharedPrefs.edit {
            putString(KEY_DISPLAY_NAME, displayName)
        }
        Log.d(TAG, "Display name saved to SharedPreferences.")
    }

    @Deprecated("Use DataStore instead for display name")
    fun getDisplayNameSharedPrefs(): String? {
        val sharedPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return sharedPrefs.getString(KEY_DISPLAY_NAME, null)
    }
}
