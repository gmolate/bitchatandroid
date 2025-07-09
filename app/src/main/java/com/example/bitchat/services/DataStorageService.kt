package com.example.bitchat.services

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64 // Using android.util.Base64 for consistency
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit as dsEdit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.bitchat.viewmodel.UiMessage // Assuming UiMessage is in viewmodel package
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator // Added for Identity Key generation directly in Keystore
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator // Added for Channel Wrapping Key generation
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.concurrent.ConcurrentHashMap


val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "bitchat_settings_v2") // v2 for safety with new structures

class DataStorageService(private val context: Context) {

    companion object {
        private const val TAG = "BitChatDataStore" // Consistent TAG prefix

        val DISPLAY_NAME_DS_KEY = stringPreferencesKey("display_name_ds_v2")
        val USER_EPHEMERAL_ID_DS_KEY = stringPreferencesKey("user_ephemeral_id_ds_v2")
        val PEER_PUBLIC_KEYS_DS_KEY = stringPreferencesKey("peer_public_keys_map_v3")

        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val IDENTITY_KEY_ALIAS = "BitChat_UserIdentityKey_Ed25519_v2"
        private const val CHANNEL_PASSWORD_KEY_ALIAS_PREFIX = "BitChat_ChannelWrapKey_"

        private const val KEYSTORE_AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    }

    private val gson = Gson()
    private val uiMessageListTypeToken = object : TypeToken<List<UiMessage>>() {}.type
    private val peerPublicKeysMapTypeToken = object : TypeToken<Map<String, String>>() {}.type

    private val peerPublicKeysCache = ConcurrentHashMap<String, ByteArray>()
    private val channelKeyCache = ConcurrentHashMap<String, SecretKey>() // Cache for decrypted channel keys

    // --- User Preferences ---
    val displayNameFlow: Flow<String?> = context.dataStore.data
        .catch { exception ->
            Log.e(TAG, "Error reading displayNameFlow from DataStore.", exception)
            if (exception is IOException) emit(emptyPreferences()) else throw exception
        }
        .map { preferences -> preferences[DISPLAY_NAME_DS_KEY] }

    suspend fun saveDisplayName(displayName: String) {
        Log.d(TAG, "Saving display name: '$displayName'")
        context.dataStore.dsEdit { settings -> settings[DISPLAY_NAME_DS_KEY] = displayName }
        Log.i(TAG, "Display name '$displayName' saved to DataStore.")
    }

    val userEphemeralIdFlow: Flow<String?> = context.dataStore.data
        .catch { exception ->
            Log.e(TAG, "Error reading userEphemeralIdFlow from DataStore.", exception)
            if (exception is IOException) emit(emptyPreferences()) else throw exception
        }
        .map { preferences -> preferences[USER_EPHEMERAL_ID_DS_KEY] }

    suspend fun saveUserEphemeralId(ephemeralId: String) {
        Log.d(TAG, "Saving user ephemeral ID: '$ephemeralId'")
        context.dataStore.dsEdit { settings -> settings[USER_EPHEMERAL_ID_DS_KEY] = ephemeralId }
        Log.i(TAG, "User ephemeral ID '$ephemeralId' saved to DataStore.")
    }

    suspend fun getUserEphemeralId(): String? {
        Log.d(TAG, "Getting user ephemeral ID from DataStore.")
        val id = userEphemeralIdFlow.firstOrNull()
        Log.d(TAG, "User ephemeral ID from DataStore: ${id ?: "Not found"}")
        return id
    }

    // --- Persistent Identity Key (Ed25519 using Android Keystore) ---
    fun getOrGenerateIdentityKeyPair(): KeyPair? {
        Log.d(TAG, "Attempting to get or generate Ed25519 identity key pair from Android Keystore (Alias: $IDENTITY_KEY_ALIAS).")
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            val privateKey = keyStore.getKey(IDENTITY_KEY_ALIAS, null) as? PrivateKey
            val publicKey = keyStore.getCertificate(IDENTITY_KEY_ALIAS)?.publicKey

            if (privateKey != null && publicKey != null) {
                Log.i(TAG, "Ed25519 identity key pair loaded from Keystore. PubKey Algo: ${publicKey.algorithm}")
                return KeyPair(publicKey, privateKey)
            } else {
                Log.i(TAG, "Identity key pair not found in Keystore. Generating new Ed25519 key pair.")
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE_PROVIDER)
                val parameterSpec = KeyGenParameterSpec.Builder(
                    IDENTITY_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                ).run {
                    // For Ed25519, KeyProperties.KEY_ALGORITHM_EC with EdDSA signature scheme is used.
                    // Android P (API 28) added support for Ed25519.
                    // No explicit curve needed if KeyPairGenerator with "AndroidKeyStore" handles "EC" for Ed25519.
                    // setAlgorithmParameterSpec(EdDSAParameterSpec(EdDSAParameterSpec.ED25519)) // Might be needed if using BC directly
                    setDigests(KeyProperties.DIGEST_NONE) // EdDSA performs its own hashing
                    build()
                }
                kpg.initialize(parameterSpec)
                val kp = kpg.generateKeyPair()
                Log.i(TAG, "New Ed25519 identity key pair generated and stored in Keystore. PubKey Algo: ${kp.public.algorithm}")
                return kp
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error accessing or generating Ed25519 identity key pair: ${e.message}", e)
            return null
        }
    }

    // --- Channel Password Derived Key Storage (AES key wrapping in Keystore) ---
    fun saveChannelKey(channelName: String, keyToProtect: SecretKey): Boolean {
        val alias = CHANNEL_PASSWORD_KEY_ALIAS_PREFIX + channelName.hashCode().toString()
        Log.d(TAG, "Saving channel key for '$channelName' using Keystore alias '$alias'. Key to protect length: ${keyToProtect.encoded.size}B")
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            if (!keyStore.containsAlias(alias)) {
                Log.d(TAG, "Wrapping key for alias '$alias' not found, generating new AES-256 GCM key in Keystore.")
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER)
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGenerator.init(spec)
                keyGenerator.generateKey()
                Log.i(TAG, "New wrapping key generated for alias '$alias'.")
            }

            val keystoreWrappingKey = keyStore.getKey(alias, null) as SecretKey
            val cipher = Cipher.getInstance(KEYSTORE_AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, keystoreWrappingKey) // IV is generated by Cipher for encryption

            val encryptedKey = cipher.doFinal(keyToProtect.encoded)
            val iv = cipher.iv

            context.dataStore.dsEdit { settings ->
                settings[stringPreferencesKey("enc_channel_key_b64_$channelName")] = Base64.encodeToString(encryptedKey, Base64.NO_WRAP)
                settings[stringPreferencesKey("enc_channel_iv_b64_$channelName")] = Base64.encodeToString(iv, Base64.NO_WRAP)
            }
            Log.i(TAG, "Channel key for '$channelName' (size ${keyToProtect.encoded.size}B) encrypted (to ${encryptedKey.size}B with ${iv.size}B IV) and stored.")
            channelKeyCache[channelName] = keyToProtect // Cache the original key
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error saving channel key for '$channelName': ${e.message}", e)
            return false
        }
    }

    suspend fun getChannelKey(channelName: String): SecretKey? {
        if (channelKeyCache.containsKey(channelName)) {
            Log.d(TAG, "Returning cached channel key for '$channelName'.")
            return channelKeyCache[channelName]
        }
        val alias = CHANNEL_PASSWORD_KEY_ALIAS_PREFIX + channelName.hashCode().toString()
        Log.d(TAG, "Attempting to retrieve and decrypt channel key for '$channelName' using Keystore alias '$alias'.")
        try {
            val preferences = context.dataStore.data.firstOrNull() ?: run { Log.w(TAG, "DataStore preferences not found for channel '$channelName'."); return null }
            val encryptedKeyB64 = preferences[stringPreferencesKey("enc_channel_key_b64_$channelName")] ?: run { Log.w(TAG, "Encrypted channel key not found in DataStore for '$channelName'."); return null }
            val ivB64 = preferences[stringPreferencesKey("enc_channel_iv_b64_$channelName")] ?: run { Log.w(TAG, "IV for channel key not found in DataStore for '$channelName'."); return null }

            val encryptedKey = Base64.decode(encryptedKeyB64, Base64.NO_WRAP)
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            if (!keyStore.containsAlias(alias)) {
                Log.w(TAG, "Keystore wrapping key for channel '$channelName' (alias '$alias') not found.")
                return null
            }
            val keystoreWrappingKey = keyStore.getKey(alias, null) as SecretKey

            val cipher = Cipher.getInstance(KEYSTORE_AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(EncryptionService.GCM_TAG_LENGTH_BYTES * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, keystoreWrappingKey, spec)

            val decryptedKeyBytes = cipher.doFinal(encryptedKey)
            val finalKey = SecretKeySpec(decryptedKeyBytes, "AES")
            Log.i(TAG, "Channel key for '$channelName' (decrypted size ${finalKey.encoded.size}B) retrieved and decrypted successfully.")
            channelKeyCache[channelName] = finalKey
            return finalKey
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving or decrypting channel key for '$channelName': ${e.message}", e)
            return null
        }
    }

    suspend fun deleteChannelKey(channelName: String) {
        val alias = CHANNEL_PASSWORD_KEY_ALIAS_PREFIX + channelName.hashCode().toString()
        Log.d(TAG, "Deleting channel key and Keystore entry for '$channelName' (alias '$alias').")
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
                Log.i(TAG, "Keystore entry for alias '$alias' deleted.")
            }
            context.dataStore.dsEdit { settings ->
                settings.remove(stringPreferencesKey("enc_channel_key_b64_$channelName"))
                settings.remove(stringPreferencesKey("enc_channel_iv_b64_$channelName"))
            }
            channelKeyCache.remove(channelName)
            Log.i(TAG, "Channel key data for '$channelName' deleted from DataStore and cache.")
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting channel key for '$channelName': ${e.message}", e)
        }
    }

    // --- Message Persistence ---
    private fun dsKeyMessagesForChannel(channelName: String) = stringPreferencesKey("messages_json_${channelName.replace("#", "")}_v2")

    suspend fun addMessageToChannel(channelName: String, message: UiMessage) {
        Log.d(TAG, "Adding message ID ${message.id} to channel '$channelName'.")
        context.dataStore.dsEdit { settings ->
            val currentMessagesJson = settings[dsKeyMessagesForChannel(channelName)]
            val currentMessages: MutableList<UiMessage> = if (currentMessagesJson != null) {
                try {
                    gson.fromJson(currentMessagesJson, uiMessageListTypeToken)
                } catch (e: Exception) {
                    Log.e(TAG, "Error parsing existing messages for channel '$channelName', starting fresh list.", e)
                    mutableListOf()
                }
            } else {
                mutableListOf()
            }
            currentMessages.add(message)
            settings[dsKeyMessagesForChannel(channelName)] = gson.toJson(currentMessages)
            Log.i(TAG, "Message ID ${message.id} added to DataStore for channel '$channelName'. Total messages: ${currentMessages.size}")
        }
    }

    fun getMessagesForChannel(channelName: String): Flow<List<UiMessage>> {
        Log.d(TAG, "Getting messages flow for channel '$channelName'.")
        return context.dataStore.data
            .catch { exception ->
                Log.e(TAG, "Error reading messages DataStore for channel '$channelName'.", exception)
                if (exception is IOException) emit(emptyPreferences()) else throw exception
            }
            .map { preferences ->
                val messagesJson = preferences[dsKeyMessagesForChannel(channelName)]
                if (messagesJson != null) {
                    try {
                        val msgs = gson.fromJson<List<UiMessage>>(messagesJson, uiMessageListTypeToken) ?: emptyList()
                        Log.d(TAG, "Loaded ${msgs.size} messages from JSON for channel '$channelName'.")
                        msgs
                    } catch (e: Exception) {
                        Log.e(TAG, "Error parsing messages JSON for channel '$channelName'.", e)
                        emptyList()
                    }
                } else {
                    Log.d(TAG, "No messages JSON found for channel '$channelName'. Returning empty list.")
                    emptyList()
                }
            }
    }

    suspend fun clearMessagesForChannel(channelName: String) {
        Log.i(TAG, "Clearing messages for channel '$channelName'.")
        context.dataStore.dsEdit { settings ->
            settings.remove(dsKeyMessagesForChannel(channelName))
        }
    }

    suspend fun clearAllMessages() {
        Log.w(TAG, "Clearing ALL messages from ALL channels. This is a destructive operation.")
        context.dataStore.dsEdit { settings ->
            val keysToRemove = settings.asMap().keys.filter { it.name.startsWith("messages_json_") }
            Log.d(TAG, "Found ${keysToRemove.size} message list keys to remove.")
            for (key in keysToRemove) {
                settings.remove(key)
            }
        }
        Log.i(TAG, "All channel messages cleared from DataStore.")
    }

    // --- Peer Public Key Management ---
    suspend fun preloadPeerPublicKeysCache() {
        if (peerPublicKeysCache.isEmpty()) {
            Log.i(TAG, "Preloading peer public keys into cache.")
            val allKeys = loadPeerPublicKeysFromDataStore()
            allKeys.forEach { (id, key) -> peerPublicKeysCache[id] = key }
            Log.i(TAG, "Preloaded ${peerPublicKeysCache.size} peer public keys into cache.")
        } else {
            Log.d(TAG, "Peer public key cache already populated (${peerPublicKeysCache.size} keys). No preload needed.")
        }
    }

    private suspend fun loadPeerPublicKeysFromDataStore(): Map<String, ByteArray> {
        Log.d(TAG, "Loading all peer public keys from DataStore (Key: ${PEER_PUBLIC_KEYS_DS_KEY.name}).")
        val jsonString = context.dataStore.data
            .map { preferences -> preferences[PEER_PUBLIC_KEYS_DS_KEY] ?: "{}" }
            .firstOrNull() ?: "{}"
        return try {
            val base64Map: Map<String, String> = gson.fromJson(jsonString, peerPublicKeysMapTypeToken) ?: emptyMap()
            val loadedKeys = base64Map.mapValues { (peerId, b64Key) ->
                try { Base64.decode(b64Key, Base64.NO_WRAP) }
                catch (e: IllegalArgumentException) { Log.e(TAG, "Error decoding Base64 for peer $peerId public key.", e); ByteArray(0) }
            }.filterValues { it.isNotEmpty() }
            Log.i(TAG, "Loaded ${loadedKeys.size} peer public keys from DataStore.")
            loadedKeys
        } catch (e: Exception) {
            Log.e(TAG, "Error deserializing peer public keys JSON from DataStore.", e)
            emptyMap()
        }
    }

    private suspend fun savePeerPublicKeysToDataStore(keys: Map<String, ByteArray>) {
        Log.d(TAG, "Saving ${keys.size} peer public keys to DataStore (Key: ${PEER_PUBLIC_KEYS_DS_KEY.name}).")
        val base64Map = keys.mapValues { (_, value) -> Base64.encodeToString(value, Base64.NO_WRAP) }
        val jsonString = gson.toJson(base64Map)
        context.dataStore.dsEdit { settings -> settings[PEER_PUBLIC_KEYS_DS_KEY] = jsonString }
        Log.i(TAG, "Successfully saved ${keys.size} peer public keys to DataStore.")
    }

    suspend fun getPeerPublicKey(peerId: String): ByteArray? {
        peerPublicKeysCache[peerId]?.let {
            Log.d(TAG, "Retrieved public key for peer '$peerId' from cache.")
            return it
        }
        Log.d(TAG, "Public key for peer '$peerId' not in cache. Attempting to load from DataStore (will load all if cache was empty).")
        // Ensure cache is populated if it was empty
        if (peerPublicKeysCache.isEmpty()) { preloadPeerPublicKeysCache() }

        val keyFromStore = peerPublicKeysCache[peerId] // Try again after potential preload
        if (keyFromStore != null) {
             Log.d(TAG, "Retrieved public key for peer '$peerId' from DataStore (via cache refresh).")
        } else {
            Log.w(TAG, "Public key for peer '$peerId' not found in cache or DataStore.")
        }
        return keyFromStore
    }

    suspend fun savePeerPublicKey(peerId: String, publicKey: ByteArray) {
        if (publicKey.isEmpty()) {
            Log.w(TAG, "Attempted to save an empty public key for peer '$peerId'. Ignoring.")
            return
        }
        val currentKey = peerPublicKeysCache[peerId]
        if (currentKey != null && currentKey.contentEquals(publicKey)) {
            Log.d(TAG, "Public key for peer '$peerId' is already up-to-date in cache. No change made to DataStore.")
            return
        }
        Log.i(TAG, "Saving/Updating public key for peer '$peerId' (Size: ${publicKey.size}B). Current cache size: ${peerPublicKeysCache.size}")
        peerPublicKeysCache[peerId] = publicKey
        savePeerPublicKeysToDataStore(HashMap(peerPublicKeysCache)) // Save a copy of the cache
    }
}
