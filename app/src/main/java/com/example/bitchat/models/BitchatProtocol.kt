package com.example.bitchat.models

import android.util.Log // For logging within BinaryProtocol
import com.example.bitchat.services.EncryptionService // Needed for context in serialization
// TODO: Import actual LZ4Util and PKCS7Util once implemented
// import com.example.bitchat.utils.CompressionUtil
// import com.example.bitchat.utils.PKCS7Util
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

// --- Core Data Structures ---

// Placeholder for actual utility classes that would be in com.example.bitchat.utils
object LZ4Util {
    fun compress(data: ByteArray): ByteArray { Log.d("LZ4Util", "Placeholder compress called"); return data }
    fun decompress(data: ByteArray, originalLength: Int): ByteArray { Log.d("LZ4Util", "Placeholder decompress called"); return data }
}
object PKCS7Util {
    fun pad(data: ByteArray, blockSize: Int): ByteArray { Log.d("PKCS7Util", "Placeholder pad called"); return data }
    fun unpad(data: ByteArray): ByteArray? { Log.d("PKCS7Util", "Placeholder unpad called"); return data }
}
// object LZ4Util {
//     fun compress(data: ByteArray): ByteArray { /* TODO */ return data }
//     fun decompress(data: ByteArray): ByteArray { /* TODO */ return data }
// }
// object PKCS7Util {
//     fun pad(data: ByteArray, blockSize: Int): ByteArray { /* TODO */ return data }
//     fun unpad(data: ByteArray): ByteArray? { /* TODO */ return data }
// }


/**
 * Represents the overall packet structure in the BitChat protocol.
 *
 * Mimics the Swift BitchatPacket structure:
 * struct BitchatPacket: Codable {
 *     let id: UUID          // Unique packet identifier
 *     let sourceId: String  // Ephemeral ID of the sender
 *     let message: BitchatMessage // The actual message content
 *     let timestamp: Date   // Timestamp of when the packet was created
 *     let ttl: Int          // Time-to-live for store-and-forward
 *     var hops: Int = 0     // Number of hops this packet has taken
 *     var rssiAtLastHop: Int? // Optional RSSI at the last hop for metrics
 *     var signature: Data?  // Optional Ed25519 signature of (id, sourceId, message, timestamp, ttl, hops)
 * }
 */
data class BitchatPacket(
    val id: UUID = UUID.randomUUID(),
    val sourceId: String, // Ephemeral Peer ID (String in iOS, likely a UUID string)
    val message: BitchatMessage,
    val timestamp: Long = System.currentTimeMillis(), // Using Long for timestamp (Date in Swift)
    val ttl: Int,
    var hops: Int = 0,
    var rssiAtLastHop: Int? = null,
    var signature: ByteArray? = null // Ed25519 signature
) {
    // Data to be signed: (id, sourceId, message bytes, timestamp, ttl, hops)
    fun dataToSign(messageBytes: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(16 + 4 + sourceId.toByteArray(Charsets.UTF_8).size + 4 + messageBytes.size + 8 + 4 + 4)
            .order(ByteOrder.BIG_ENDIAN) // Consistent with typical network order

        buffer.putLong(id.mostSignificantBits)
        buffer.putLong(id.leastSignificantBits)

        val sourceIdBytes = sourceId.toByteArray(Charsets.UTF_8)
        buffer.putInt(sourceIdBytes.size)
        buffer.put(sourceIdBytes)

        buffer.putInt(messageBytes.size)
        buffer.put(messageBytes)

        buffer.putLong(timestamp)
        buffer.putInt(ttl)
        buffer.putInt(hops)
        // rssiAtLastHop is not part of the signature in the iOS version from what I remember.
        return buffer.array()
    }
}

/**
 * Represents the core message content within a BitchatPacket.
 *
 * Mimics the Swift BitchatMessage structure:
 * enum BitchatMessage: Codable {
 *     case announce(peerId: String, displayName: String, publicKey: Data)
 *     case keyExchangeRequest(peerId: String, ephemeralPublicKey: Data)
 *     case keyExchangeResponse(peerId: String, ephemeralPublicKey: Data)
 *     case userMessage(channel: String, senderDisplayName: String, text: String, isPrivate: Bool, isCompressed: Bool)
 *     case fragment(originalMessageId: UUID, fragmentIndex: Int, totalFragments: Int, data: Data)
 *     case ack(messageId: UUID)
 *     case channelJoinRequest(channel: String, passwordHash: Data?) // passwordHash is PBKDF2 derived
 *     case channelJoinResponse(channel: String, success: Bool, error: String?)
 *     case channelCreateRequest(channel: String, passwordHash: Data?)
 *     case channelCreateResponse(channel: String, success: Bool, error: String?)
 *     // ... other message types like error, ping, pong if defined
 * }
 */
sealed class BitchatMessage {
    abstract val typeByte: Byte

    data class Announce(
        val peerId: String, // Ephemeral Peer ID
        val displayName: String,
        val publicKey: ByteArray // Ed25519 Public Key
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x01
        // TODO: equals/hashCode for ByteArray
    }

    data class KeyExchangeRequest(
        val peerId: String, // Ephemeral Peer ID of requester
        val ephemeralPublicKey: ByteArray // X25519 Ephemeral Public Key
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x02
        // TODO: equals/hashCode for ByteArray
    }

    data class KeyExchangeResponse(
        val peerId: String, // Ephemeral Peer ID of responder
        val ephemeralPublicKey: ByteArray // X25519 Ephemeral Public Key
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x03
        // TODO: equals/hashCode for ByteArray
    }

    data class UserMessage(
        val channel: String,
        val senderDisplayName: String,
        val text: String,
        val isPrivate: Boolean,
        var isCompressed: Boolean // This might be set by BinaryProtocol during serialization
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x04
    }

    data class Fragment(
        val originalMessageId: UUID,
        val fragmentIndex: Int,
        val totalFragments: Int,
        val data: ByteArray
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x05
        // TODO: equals/hashCode for ByteArray
    }

    data class Ack(
        val messageId: UUID
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x06
    }

    data class ChannelJoinRequest(
        val channel: String,
        val passwordHash: ByteArray? = null // PBKDF2 derived hash
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x07
        // TODO: equals/hashCode for ByteArray
    }

    data class ChannelJoinResponse(
        val channel: String,
        val success: Boolean,
        val error: String? = null
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x08
    }

    data class ChannelCreateRequest(
        val channel: String,
        val passwordHash: ByteArray? = null
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x09
        // TODO: equals/hashCode for ByteArray
    }

    data class ChannelCreateResponse(
        val channel: String,
        val success: Boolean,
        val error: String? = null
    ) : BitchatMessage() {
        override val typeByte: Byte = 0x0A
    }

    // Add other message types here if they exist in the iOS protocol
    // e.g., ErrorMessage, Ping, Pong
}


// --- Binary Protocol for Serialization/Deserialization ---
// This could be a separate BinaryProtocol.kt file
object BinaryProtocol {
    private const val TAG = "BinaryProtocol"
    private const val LZ4_COMPRESSION_THRESHOLD = 100 // Bytes, example value
    private const val AES_BLOCK_SIZE = 16 // Bytes, for PKCS7 padding with AES

    // --- Serialization ---

    fun serializePacket(packet: BitchatPacket, encryptionService: EncryptionService, sharedSecret: ByteArray? = null): ByteArray? {
        try {
            var messagePayload = serializeMessage(packet.message, encryptionService, sharedSecret) ?: return null

            // Sign the packet *before* any further processing of the message payload for fragmentation
            // The signature covers the original, potentially unfragmented message form.
            // However, typical BLE MTU limits mean we'll likely send BitchatMessage, not full BitchatPacket as one BLE characteristic write.
            // The iOS app likely sends BitchatMessage, then the BLE service fragments it.
            // For now, let's assume the BitchatPacket signature (if present) signs the serialized BitchatMessage.
            // This needs to be verified against the iOS app's exact behavior.
            // If the packet.signature is for the *entire* BitchatPacket (excluding signature itself),
            // then this signing step should happen last on the fully assembled packet.
            // Let's assume for now signature is on (id, sourceId, messageBytes, timestamp, ttl, hops)

            val dataToSign = packet.dataToSign(messagePayload)
            // packet.signature = encryptionService.signEd25519(dataToSign, /* sender's Ed25519 private key */)
            // The private key for signing needs to be available. This is usually the device's identity key.
            // This part needs careful integration with key management.

            // The following is a conceptual serialization of the BitchatPacket structure.
            // In practice, for BLE, you'd likely serialize BitchatMessage and handle fragmentation at a lower layer.
            // This serialization is more for if the entire packet were to be sent as one unit.

            val buffer = ByteBuffer.allocate(1024 * 10) // Generous buffer, calculate more precisely
                .order(ByteOrder.BIG_ENDIAN)

            // Packet ID (UUID)
            buffer.putLong(packet.id.mostSignificantBits)
            buffer.putLong(packet.id.leastSignificantBits)

            // Source ID (String)
            val sourceIdBytes = packet.sourceId.toByteArray(Charsets.UTF_8)
            buffer.putInt(sourceIdBytes.size)
            buffer.put(sourceIdBytes)

            // Message (byte array from serializeMessage)
            buffer.putInt(messagePayload.size)
            buffer.put(messagePayload)

            // Timestamp (Long)
            buffer.putLong(packet.timestamp)
            // TTL (Int)
            buffer.putInt(packet.ttl)
            // Hops (Int)
            buffer.putInt(packet.hops)

            // RSSI At Last Hop (Optional Int)
            buffer.put(if (packet.rssiAtLastHop != null) 1.toByte() else 0.toByte())
            packet.rssiAtLastHop?.let { buffer.putInt(it) }

            // Signature (Optional ByteArray)
            buffer.put(if (packet.signature != null) 1.toByte() else 0.toByte())
            packet.signature?.let {
                buffer.putInt(it.size)
                buffer.put(it)
            }

            val finalPacketBytes = ByteArray(buffer.position())
            buffer.flip()
            buffer.get(finalPacketBytes)
            return finalPacketBytes

        } catch (e: Exception) {
            Log.e(TAG, "Error serializing BitchatPacket: ${e.message}", e)
            return null
        }
    }


    fun serializeMessage(message: BitchatMessage, encryptionService: EncryptionService, sharedSecret: ByteArray? = null): ByteArray? {
        try {
            val payloadBuffer = ByteBuffer.allocate(1024 * 5).order(ByteOrder.BIG_ENDIAN) // Temp buffer for message payload
            payloadBuffer.put(message.typeByte)

            when (message) {
                is BitchatMessage.Announce -> {
                    putString(payloadBuffer, message.peerId)
                    putString(payloadBuffer, message.displayName)
                    putByteArray(payloadBuffer, message.publicKey)
                }
                is BitchatMessage.KeyExchangeRequest -> {
                    putString(payloadBuffer, message.peerId)
                    putByteArray(payloadBuffer, message.ephemeralPublicKey)
                }
                is BitchatMessage.KeyExchangeResponse -> {
                    putString(payloadBuffer, message.peerId)
                    putByteArray(payloadBuffer, message.ephemeralPublicKey)
                }
                is BitchatMessage.UserMessage -> {
                    putString(payloadBuffer, message.channel)
                    putString(payloadBuffer, message.senderDisplayName)

                    var textBytes = message.text.toByteArray(Charsets.UTF_8)
                    var finalPayload = textBytes

                    // Compression (if applicable and not private, or if private and compressed before encryption)
                    // The iOS implementation seems to compress *before* potential encryption for private messages.
                    var isActuallyCompressed = false
                    if (message.isCompressed && textBytes.size > LZ4_COMPRESSION_THRESHOLD) {
                        // val compressed = LZ4Util.compress(textBytes)
                        // if (compressed.size < textBytes.size) { // Only use if smaller
                        //    finalPayload = compressed
                        //    isActuallyCompressed = true
                        // }
                        // For now, placeholder:
                        Log.d(TAG, "Placeholder: Would attempt LZ4 compression for UserMessage")
                        isActuallyCompressed = message.isCompressed // Assume it worked if requested
                    }

                    // Encryption for private messages
                    if (message.isPrivate) {
                        if (sharedSecret == null) {
                            Log.e(TAG, "Cannot encrypt private message: shared secret is null.")
                            return null
                        }
                        // Derive AES key from shared secret (e.g., using HKDF)
                        // val aesKeyBytes = encryptionService.hkdf(sharedSecret, null, "BitChatAESKey".toByteArray(), AES_KEY_SIZE / 8)
                        // val aesKey = SecretKeySpec(aesKeyBytes, "AES")
                        // Log.d(TAG, "Placeholder: Would derive AES key for private UserMessage")
                        val aesKey = SecretKeySpec(sharedSecret.copyOfRange(0, AES_KEY_SIZE/8), "AES") // Simplified for now

                        // PKCS#7 Padding before encryption
                        // finalPayload = PKCS7Util.pad(finalPayload, AES_BLOCK_SIZE)
                        Log.d(TAG, "Placeholder: Would PKCS7 pad for private UserMessage")


                        // val encryptionResult = encryptionService.encryptAES_GCM(finalPayload, aesKey, null /* AAD if any */)
                        // if (encryptionResult == null) {
                        //     Log.e(TAG, "Failed to encrypt private UserMessage")
                        //     return null
                        // }
                        // val iv = encryptionResult.first
                        // val encryptedDataWithTag = encryptionResult.second
                        // finalPayload = iv + encryptedDataWithTag // Prepend IV
                        Log.d(TAG, "Placeholder: Would AES-GCM encrypt private UserMessage")
                    }

                    payloadBuffer.put(if (message.isPrivate) 1.toByte() else 0.toByte())
                    payloadBuffer.put(if (isActuallyCompressed) 1.toByte() else 0.toByte())
                    putByteArray(payloadBuffer, finalPayload)
                }
                is BitchatMessage.Fragment -> {
                    payloadBuffer.putLong(message.originalMessageId.mostSignificantBits)
                    payloadBuffer.putLong(message.originalMessageId.leastSignificantBits)
                    payloadBuffer.putInt(message.fragmentIndex)
                    payloadBuffer.putInt(message.totalFragments)
                    putByteArray(payloadBuffer, message.data)
                }
                is BitchatMessage.Ack -> {
                    payloadBuffer.putLong(message.messageId.mostSignificantBits)
                    payloadBuffer.putLong(message.messageId.leastSignificantBits)
                }
                is BitchatMessage.ChannelJoinRequest -> {
                    putString(payloadBuffer, message.channel)
                    payloadBuffer.put(if (message.passwordHash != null) 1.toByte() else 0.toByte())
                    message.passwordHash?.let { putByteArray(payloadBuffer, it) }
                }
                is BitchatMessage.ChannelJoinResponse -> {
                    putString(payloadBuffer, message.channel)
                    payloadBuffer.put(if (message.success) 1.toByte() else 0.toByte())
                    payloadBuffer.put(if (message.error != null) 1.toByte() else 0.toByte())
                    message.error?.let { putString(payloadBuffer, it) }
                }
                 is BitchatMessage.ChannelCreateRequest -> {
                    putString(payloadBuffer, message.channel)
                    payloadBuffer.put(if (message.passwordHash != null) 1.toByte() else 0.toByte())
                    message.passwordHash?.let { putByteArray(payloadBuffer, it) }
                }
                is BitchatMessage.ChannelCreateResponse -> {
                    putString(payloadBuffer, message.channel)
                    payloadBuffer.put(if (message.success) 1.toByte() else 0.toByte())
                    payloadBuffer.put(if (message.error != null) 1.toByte() else 0.toByte())
                    message.error?.let { putString(payloadBuffer, it) }
                }
                // Add other cases
            }

            val resultBytes = ByteArray(payloadBuffer.position())
            payloadBuffer.flip()
            payloadBuffer.get(resultBytes)
            return resultBytes

        } catch (e: Exception) {
            Log.e(TAG, "Error serializing BitchatMessage: ${e.message}", e)
            return null
        }
    }

    // --- Deserialization ---

    fun deserializePacket(data: ByteArray, encryptionService: EncryptionService, sharedSecret: ByteArray? = null): BitchatPacket? {
         try {
            val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

            val mostSigBits = buffer.long
            val leastSigBits = buffer.long
            val packetId = UUID(mostSigBits, leastSigBits)

            val sourceId = getString(buffer)

            val messageLength = buffer.int
            val messageBytes = ByteArray(messageLength)
            buffer.get(messageBytes)
            val bitchatMessage = deserializeMessage(messageBytes, encryptionService, sharedSecret) ?: return null

            val timestamp = buffer.long
            val ttl = buffer.int
            val hops = buffer.int

            val hasRssi = buffer.get() == 1.toByte()
            val rssi = if (hasRssi) buffer.int else null

            val hasSignature = buffer.get() == 1.toByte()
            val signature = if (hasSignature) getByteArray(buffer) else null

            val packet = BitchatPacket(packetId, sourceId, bitchatMessage, timestamp, ttl, hops, rssi, signature)

            // Verify signature if present
            // if (signature != null) {
            //     val expectedDataToSign = packet.dataToSign(messageBytes) // Use the raw messageBytes for verification
            //     // val senderPublicKey = ... get sender's Ed25519 public key based on sourceId (e.g., from an Announce message)
            //     // if (!encryptionService.verifyEd25519(expectedDataToSign, signature, senderPublicKey)) {
            //     //    Log.w(TAG, "Packet signature verification failed for packet ID: $packetId")
            //     //    return null // Or handle as potentially compromised packet
            //     // }
            // }
            return packet

        } catch (e: Exception) {
            Log.e(TAG, "Error deserializing BitchatPacket: ${e.message}", e)
            return null
        }
    }


    fun deserializeMessage(data: ByteArray, encryptionService: EncryptionService, sharedSecret: ByteArray? = null): BitchatMessage? {
        try {
            val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val typeByte = buffer.get()

            return when (typeByte) {
                0x01.toByte() -> BitchatMessage.Announce(getString(buffer), getString(buffer), getByteArray(buffer))
                0x02.toByte() -> BitchatMessage.KeyExchangeRequest(getString(buffer), getByteArray(buffer))
                0x03.toByte() -> BitchatMessage.KeyExchangeResponse(getString(buffer), getByteArray(buffer))
                0x04.toByte() -> {
                    val channel = getString(buffer)
                    val senderDisplayName = getString(buffer)
                    val isPrivate = buffer.get() == 1.toByte()
                    val isCompressed = buffer.get() == 1.toByte()
                    var payload = getByteArray(buffer)

                    if (isPrivate) {
                        if (sharedSecret == null) {
                            Log.e(TAG, "Cannot decrypt private message: shared secret is null.")
                            return null
                        }
                        // val iv = payload.copyOfRange(0, GCM_IV_LENGTH)
                        // val encryptedDataWithTag = payload.copyOfRange(GCM_IV_LENGTH, payload.size)
                        // val aesKeyBytes = encryptionService.hkdf(sharedSecret, null, "BitChatAESKey".toByteArray(), AES_KEY_SIZE / 8)
                        // val aesKey = SecretKeySpec(aesKeyBytes, "AES")
                        // Log.d(TAG, "Placeholder: Would derive AES key for private UserMessage")
                        val aesKey = SecretKeySpec(sharedSecret.copyOfRange(0, AES_KEY_SIZE/8), "AES") // Simplified for now

                        // payload = encryptionService.decryptAES_GCM(encryptedDataWithTag, aesKey, iv, null) ?: return null
                        // payload = PKCS7Util.unpad(payload) ?: return null // Unpad after decryption
                        Log.d(TAG, "Placeholder: Would AES-GCM decrypt and PKCS7 unpad private UserMessage")
                    }

                    if (isCompressed) {
                        // payload = LZ4Util.decompress(payload)
                        Log.d(TAG, "Placeholder: Would attempt LZ4 decompression for UserMessage")
                    }
                    BitchatMessage.UserMessage(channel, senderDisplayName, payload.toString(Charsets.UTF_8), isPrivate, isCompressed)
                }
                0x05.toByte() -> BitchatMessage.Fragment(
                    UUID(buffer.long, buffer.long),
                    buffer.int,
                    buffer.int,
                    getByteArray(buffer)
                )
                0x06.toByte() -> BitchatMessage.Ack(UUID(buffer.long, buffer.long))
                0x07.toByte() -> {
                    val channel = getString(buffer)
                    val hasPass = buffer.get() == 1.toByte()
                    BitchatMessage.ChannelJoinRequest(channel, if(hasPass) getByteArray(buffer) else null)
                }
                0x08.toByte() -> {
                    val channel = getString(buffer)
                    val success = buffer.get() == 1.toByte()
                    val hasError = buffer.get() == 1.toByte()
                    BitchatMessage.ChannelJoinResponse(channel, success, if(hasError) getString(buffer) else null)
                }
                0x09.toByte() -> {
                    val channel = getString(buffer)
                    val hasPass = buffer.get() == 1.toByte()
                    BitchatMessage.ChannelCreateRequest(channel, if(hasPass) getByteArray(buffer) else null)
                }
                0x0A.toByte() -> {
                     val channel = getString(buffer)
                    val success = buffer.get() == 1.toByte()
                    val hasError = buffer.get() == 1.toByte()
                    BitchatMessage.ChannelCreateResponse(channel, success, if(hasError) getString(buffer) else null)
                }
                else -> {
                    Log.w(TAG, "Unknown message type: $typeByte")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error deserializing BitchatMessage: ${e.message}", e)
            return null
        }
    }

    // --- Helper functions for ByteBuffer ---
    private fun putString(buffer: ByteBuffer, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        buffer.putInt(bytes.size)
        buffer.put(bytes)
    }

    private fun getString(buffer: ByteBuffer): String {
        val length = buffer.int
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private fun putByteArray(buffer: ByteBuffer, value: ByteArray) {
        buffer.putInt(value.size)
        buffer.put(value)
    }

    private fun getByteArray(buffer: ByteBuffer): ByteArray {
        val length = buffer.int
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return bytes
    }
}
