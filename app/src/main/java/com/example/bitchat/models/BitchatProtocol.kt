package com.example.bitchat.models

import android.util.Log
import com.example.bitchat.services.EncryptionService // Needed for context in serialization
import com.example.bitchat.utils.CompressionUtil // Use actual CompressionUtil
import com.example.bitchat.utils.PaddingUtil     // Use actual PaddingUtil
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import javax.crypto.SecretKey // For sharedSecretKey type hint
import javax.crypto.spec.SecretKeySpec


/**
 * Represents the overall packet structure in the BitChat protocol.
 */
data class BitchatPacket(
    val id: UUID = UUID.randomUUID(),
    val sourceId: String, // Ephemeral Peer ID (String in iOS, likely a UUID string)
    val message: BitchatMessage, // The deserialized BitchatMessage object
    val timestamp: Long = System.currentTimeMillis(),
    val ttl: Int,
    var hops: Int = 0,
    var rssiAtLastHop: Int? = null,
    var signature: ByteArray? = null, // Ed25519 signature
    @Transient var messagePayloadBytes: ByteArray? = null // Holds the raw serialized BitchatMessage bytes. Crucial for signing/verification.
) {
    /**
     * Generates the byte array that should be signed.
     * Uses `messagePayloadBytes`. This field MUST be set before calling this method.
     * Content: id, sourceId, messagePayloadBytes, timestamp, ttl, hops
     */
    fun dataToSign(): ByteArray {
        val payloadToSign = this.messagePayloadBytes
            ?: throw IllegalStateException("messagePayloadBytes is null. It must be set before calling dataToSign for packet ID: $id. Message type: ${message::class.simpleName}")

        val sourceIdBytes = sourceId.toByteArray(Charsets.UTF_8)
        // UUID (16) + sourceId_len (4) + sourceId_bytes + payload_len (4) + payload_bytes + timestamp (8) + ttl (4) + hops (4)
        val requiredBufferSize = 16 + 4 + sourceIdBytes.size + 4 + payloadToSign.size + 8 + 4 + 4

        val buffer = ByteBuffer.allocate(requiredBufferSize).order(ByteOrder.BIG_ENDIAN)

        buffer.putLong(id.mostSignificantBits)
        buffer.putLong(id.leastSignificantBits)

        buffer.putInt(sourceIdBytes.size)
        buffer.put(sourceIdBytes)

        buffer.putInt(payloadToSign.size)
        buffer.put(payloadToSign)

        buffer.putLong(timestamp)
        buffer.putInt(ttl)
        buffer.putInt(hops)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as BitchatPacket
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

/**
 * Represents the core message content within a BitchatPacket.
 */
sealed class BitchatMessage {
    abstract val typeByte: Byte

    data class Announce(
        val peerId: String,
        val displayName: String,
        val publicKey: ByteArray
    ) : BitchatMessage() { override val typeByte: Byte = 0x01 }

    data class KeyExchangeRequest(
        val peerId: String,
        val ephemeralPublicKey: ByteArray
    ) : BitchatMessage() { override val typeByte: Byte = 0x02 }

    data class KeyExchangeResponse(
        val peerId: String,
        val ephemeralPublicKey: ByteArray
    ) : BitchatMessage() { override val typeByte: Byte = 0x03 }

    data class UserMessage(
        val channel: String,
        val senderDisplayName: String,
        val text: String,
        val isPrivate: Boolean,
        var isCompressed: Boolean
    ) : BitchatMessage() { override val typeByte: Byte = 0x04 }

    data class Fragment(
        val originalMessageId: UUID,
        val fragmentIndex: Int,
        val totalFragments: Int,
        val data: ByteArray
    ) : BitchatMessage() { override val typeByte: Byte = 0x05 }

    data class Ack(
        val messageId: UUID
    ) : BitchatMessage() { override val typeByte: Byte = 0x06 }

    data class ChannelJoinRequest(
        val channel: String,
        val passwordHash: ByteArray? = null
    ) : BitchatMessage() { override val typeByte: Byte = 0x07 }

    data class ChannelJoinResponse(
        val channel: String,
        val success: Boolean,
        val error: String? = null
    ) : BitchatMessage() { override val typeByte: Byte = 0x08 }

    data class ChannelCreateRequest(
        val channel: String,
        val passwordHash: ByteArray? = null
    ) : BitchatMessage() { override val typeByte: Byte = 0x09 }

    data class ChannelCreateResponse(
        val channel: String,
        val success: Boolean,
        val error: String? = null
    ) : BitchatMessage() { override val typeByte: Byte = 0x0A }

    // --- State Synchronization Messages (Conceptual Skeleton) ---
    /**
     * Requests state synchronization from a peer.
     * Could include hashes of known messages, channel states, etc., to help the peer determine what's missing.
     * For now, a simple request.
     */
    data class StateSyncRequest(
        val sinceTimestamp: Long? = null, // Optional: request updates since a certain time
        val requestedChannelIds: List<String>? = null // Optional: request sync for specific channels
        // Future: Could include bloom filters of known message IDs for more efficient diffing.
    ) : BitchatMessage() { override val typeByte: Byte = 0x0B }

    /**
     * Responds to a StateSyncRequest with relevant state information.
     * The actual content would be complex (e.g., list of recent messages, channel member updates).
     * For now, a placeholder.
     */
    data class StateSyncResponse(
        val forPeerId: String, // The peerId this sync response is intended for
        val messages: List<BitchatPacket>? = null, // Example: send missing messages (could be just BitchatMessage objects)
        val channelUpdates: List<ChannelInfo>? = null // Example: send channel updates
        // Future: Could include more granular updates.
    ) : BitchatMessage() { override val typeByte: Byte = 0x0C }
}


object BinaryProtocol {
    private const val TAG = "BitChatProtocol"
    private const val LZ4_COMPRESSION_THRESHOLD_BYTES = 100
    private const val AES_BLOCK_SIZE_BYTES = 16
    private const val AES_KEY_SIZE_BITS = 256
    private const val GCM_IV_LENGTH_BYTES = 12
    private const val PACKET_VERSION_1: Byte = 0x01


    fun serializePacket(packet: BitchatPacket, encryptionService: EncryptionService, sharedSecretKey: SecretKey? = null): ByteArray? {
        try {
            // Ensure messagePayloadBytes is set in the packet
            if (packet.messagePayloadBytes == null) {
                Log.d(TAG, "serializePacket: messagePayloadBytes not pre-set for packet ${packet.id}, serializing BitchatMessage now.")
                packet.messagePayloadBytes = serializeMessage(packet.message, encryptionService, sharedSecretKey)
            }
            val messagePayloadToEmbed = packet.messagePayloadBytes
                ?: run {
                    Log.e(TAG, "serializePacket: Failed to obtain/serialize message payload for packet ${packet.id}. Message type: ${packet.message::class.simpleName}")
                    return null
                }

            if (packet.signature == null) {
                Log.w(TAG, "serializePacket: Packet ${packet.id} (type ${packet.message::class.simpleName}) is being serialized without a signature.")
            }

            val baos = ByteArrayOutputStream()
            val dos = DataOutputStream(baos)

            dos.writeByte(PACKET_VERSION_1.toInt())
            dos.writeUTF(packet.id.toString())
            dos.writeUTF(packet.sourceId)
            dos.writeLong(packet.timestamp)
            dos.writeInt(packet.ttl)
            dos.writeInt(packet.hops)
            dos.writeBoolean(packet.rssiAtLastHop != null)
            packet.rssiAtLastHop?.let { dos.writeInt(it) }
            dos.writeBoolean(packet.signature != null)
            packet.signature?.let {
                dos.writeInt(it.size)
                dos.write(it)
            }
            dos.writeInt(messagePayloadToEmbed.size)
            dos.write(messagePayloadToEmbed)
            dos.flush()

            val finalPacketBytes = baos.toByteArray()
            Log.i(TAG, "serializePacket: Successfully serialized packet ${packet.id} (${packet.message::class.simpleName}) to ${finalPacketBytes.size} bytes.")
            return finalPacketBytes

        } catch (e: IOException) {
            Log.e(TAG, "serializePacket: IOException for packet ${packet.id} (${packet.message::class.simpleName}): ${e.message}", e)
            return null
        } catch (e: Exception) {
            Log.e(TAG, "serializePacket: Unexpected error for packet ${packet.id} (${packet.message::class.simpleName}): ${e.message}", e)
            return null
        }
    }

    fun deserializePacket(data: ByteArray, encryptionService: EncryptionService): BitchatPacket? {
        // Note: sharedSecretKey for decrypting private messages needs to be determined by the caller (e.g. ChatViewModel)
        // based on context (e.g. sourceId and key exchange state) and passed to deserializeMessage if needed.
        // This top-level deserializePacket doesn't have that context.
        try {
            val bais = ByteArrayInputStream(data)
            val dis = DataInputStream(bais)

            val packetVersion = dis.readByte()
            if (packetVersion != PACKET_VERSION_1) {
                Log.e(TAG, "deserializePacket: Unsupported packet version: $packetVersion. Expected $PACKET_VERSION_1. Data length: ${data.size}")
                return null
            }

            val id = UUID.fromString(dis.readUTF())
            val sourceId = dis.readUTF()
            val timestamp = dis.readLong()
            val ttl = dis.readInt()
            val hops = dis.readInt()
            val hasRssi = dis.readBoolean()
            val rssiAtLastHop = if (hasRssi) dis.readInt() else null
            val hasSignature = dis.readBoolean()
            val signature = if (hasSignature) readByteArray(dis) else null
            val readMessagePayloadBytes = readByteArray(dis)

            // TODO: The caller (e.g. ChatViewModel) needs to determine the correct sharedSecretKey if the message is private.
            // For now, passing null, which means private messages won't be decrypted here.
            val sharedSecretKeyForDecryption: SecretKey? = null

            val bitchatMessage = deserializeMessage(readMessagePayloadBytes, encryptionService, sharedSecretKeyForDecryption)
                ?: run {
                    Log.e(TAG, "deserializePacket: Failed to deserialize BitchatMessage from packet $id payload (size ${readMessagePayloadBytes.size}).")
                    return null
                }

            val packet = BitchatPacket(
                id = id, sourceId = sourceId, message = bitchatMessage, timestamp = timestamp, ttl = ttl,
                hops = hops, rssiAtLastHop = rssiAtLastHop, signature = signature,
                messagePayloadBytes = readMessagePayloadBytes // Store for signature verification
            )
            Log.i(TAG, "deserializePacket: Successfully deserialized packet ${packet.id} from ${packet.sourceId}. Type: ${packet.message::class.simpleName}, Payload size: ${packet.messagePayloadBytes?.size}")
            return packet

        } catch (e: IOException) {
            Log.e(TAG, "deserializePacket: IOException (Data length: ${data.size}): ${e.message}", e)
            return null
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "deserializePacket: IllegalArgumentException (e.g. invalid UUID) (Data length: ${data.size}): ${e.message}", e)
            return null
        } catch (e: Exception) {
            Log.e(TAG, "deserializePacket: Unexpected error (Data length: ${data.size}): ${e.message}", e)
            return null
        }
    }

    fun serializeMessage(message: BitchatMessage, encryptionService: EncryptionService, sharedSecretKey: SecretKey? = null): ByteArray? {
        try {
            val baos = ByteArrayOutputStream()
            val dos = DataOutputStream(baos)
            dos.writeByte(message.typeByte.toInt())
            Log.d(TAG, "serializeMessage: Starting type ${message::class.simpleName} (0x${message.typeByte.toString(16)})")

            when (message) {
                is BitchatMessage.Announce -> {
                    dos.writeUTF(message.peerId)
                    dos.writeUTF(message.displayName)
                    writeByteArray(dos, message.publicKey)
                }
                is BitchatMessage.KeyExchangeRequest -> {
                    dos.writeUTF(message.peerId)
                    writeByteArray(dos, message.ephemeralPublicKey)
                }
                is BitchatMessage.KeyExchangeResponse -> {
                    dos.writeUTF(message.peerId)
                    writeByteArray(dos, message.ephemeralPublicKey)
                }
                is BitchatMessage.UserMessage -> {
                    dos.writeUTF(message.channel)
                    dos.writeUTF(message.senderDisplayName)
                    var textBytes = message.text.toByteArray(Charsets.UTF_8)
                    var currentPayload = textBytes
                    var effectiveIsCompressed = false

                    if (message.isCompressed && textBytes.size > LZ4_COMPRESSION_THRESHOLD_BYTES) {
                        Log.d(TAG, "UserMessage: Attempting LZ4 for ${textBytes.size}B for channel '${message.channel}'")
                        val compressed = CompressionUtil.compress(textBytes)
                        if (compressed != null && compressed.size < textBytes.size) {
                            currentPayload = compressed
                            effectiveIsCompressed = true
                            Log.i(TAG, "UserMessage: Compressed ${textBytes.size}B -> ${currentPayload.size}B for channel '${message.channel}'.")
                        } else {
                             Log.d(TAG, "UserMessage: Compression not effective or failed for channel '${message.channel}'. Original: ${textBytes.size}B, Compressed: ${compressed?.size}B")
                        }
                    }

                    if (message.isPrivate) {
                        if (sharedSecretKey == null) {
                            Log.e(TAG, "UserMessage: Cannot encrypt private message for channel '${message.channel}'. Shared secret key is NULL.")
                            return null
                        }
                        Log.d(TAG, "UserMessage: Encrypting private message (${currentPayload.size}B) for channel '${message.channel}'.")
                        val paddedPayload = PaddingUtil.addPKCS7Padding(currentPayload, AES_BLOCK_SIZE_BYTES)
                        Log.d(TAG, "UserMessage: Padded private message for channel '${message.channel}' ${currentPayload.size}B -> ${paddedPayload.size}B.")

                        val encryptionResult = encryptionService.encryptAES_GCM(paddedPayload, sharedSecretKey, null) // AAD could be packet.id or channel name for context
                        if (encryptionResult == null) {
                            Log.e(TAG, "UserMessage: Failed to encrypt private message for channel '${message.channel}'.")
                            return null
                        }
                        val (iv, ciphertextWithTag) = encryptionResult
                        currentPayload = iv + ciphertextWithTag
                        Log.i(TAG, "UserMessage: Encrypted private message for channel '${message.channel}'. IV:${iv.size}B, Cipher+Tag:${ciphertextWithTag.size}B, Total:${currentPayload.size}B.")
                    }
                    dos.writeBoolean(message.isPrivate)
                    dos.writeBoolean(effectiveIsCompressed) // Store actual compression status
                    writeByteArray(dos, currentPayload)
                }
                is BitchatMessage.Fragment -> {
                    dos.writeUTF(message.originalMessageId.toString())
                    dos.writeInt(message.fragmentIndex)
                    dos.writeInt(message.totalFragments)
                    writeByteArray(dos, message.data)
                }
                is BitchatMessage.Ack -> dos.writeUTF(message.messageId.toString())
                is BitchatMessage.ChannelJoinRequest -> {
                    dos.writeUTF(message.channel)
                    dos.writeBoolean(message.passwordHash != null)
                    message.passwordHash?.let { writeByteArray(dos, it) }
                }
                is BitchatMessage.ChannelJoinResponse -> {
                    dos.writeUTF(message.channel)
                    dos.writeBoolean(message.success)
                    dos.writeBoolean(message.error != null)
                    message.error?.let { dos.writeUTF(it) }
                }
                is BitchatMessage.ChannelCreateRequest -> {
                    dos.writeUTF(message.channel)
                    dos.writeBoolean(message.passwordHash != null)
                    message.passwordHash?.let { writeByteArray(dos, it) }
                }
                is BitchatMessage.ChannelCreateResponse -> {
                    dos.writeUTF(message.channel)
                    dos.writeBoolean(message.success)
                    dos.writeBoolean(message.error != null)
                    message.error?.let { dos.writeUTF(it) }
                }
                is BitchatMessage.StateSyncRequest -> {
                    dos.writeBoolean(message.sinceTimestamp != null)
                    message.sinceTimestamp?.let { dos.writeLong(it) }
                    dos.writeBoolean(message.requestedChannelIds != null)
                    message.requestedChannelIds?.let { ids ->
                        dos.writeInt(ids.size)
                        ids.forEach { dos.writeUTF(it) }
                    }
                }
                is BitchatMessage.StateSyncResponse -> {
                    dos.writeUTF(message.forPeerId)
                    // Serializing lists of complex objects like BitchatPacket or ChannelInfo here
                    // would require careful handling and might be too large for a single message.
                    // This is a placeholder; actual sync would likely use smaller, more targeted messages
                    // or a multi-message exchange. For now, just indicate presence.
                    dos.writeBoolean(message.messages != null)
                    // If sending messages: dos.writeInt(message.messages.size); message.messages.forEach { serializePacket(it, ...) } - recursive, careful!
                    dos.writeBoolean(message.channelUpdates != null)
                    // If sending channel updates: dos.writeInt(message.channelUpdates.size); message.channelUpdates.forEach { serializeChannelInfo(it, dos) }
                }
            }
            dos.flush()
            val resultBytes = baos.toByteArray()
            Log.i(TAG, "serializeMessage: Successfully serialized ${message::class.simpleName} to ${resultBytes.size} bytes.")
            return resultBytes

        } catch (e: IOException) {
            Log.e(TAG, "serializeMessage: IOException for ${message::class.simpleName}: ${e.message}", e)
            return null
        } catch (e: Exception) {
            Log.e(TAG, "serializeMessage: Unexpected error for ${message::class.simpleName}: ${e.message}", e)
            return null
        }
    }

    fun deserializeMessage(data: ByteArray, encryptionService: EncryptionService, sharedSecretKey: SecretKey? = null): BitchatMessage? {
        try {
            val bais = ByteArrayInputStream(data)
            val dis = DataInputStream(bais)
            if (data.isEmpty()) {
                Log.e(TAG, "deserializeMessage: Input data is empty.")
                return null
            }
            val typeByte = dis.readByte()
            Log.d(TAG, "deserializeMessage: Attempting message type 0x${typeByte.toString(16)}")

            return when (typeByte) {
                0x01.toByte() -> BitchatMessage.Announce(dis.readUTF(), dis.readUTF(), readByteArray(dis))
                0x02.toByte() -> BitchatMessage.KeyExchangeRequest(dis.readUTF(), readByteArray(dis))
                0x03.toByte() -> BitchatMessage.KeyExchangeResponse(dis.readUTF(), readByteArray(dis))
                0x04.toByte() -> {
                    val channel = dis.readUTF()
                    val senderDisplayName = dis.readUTF()
                    val isPrivate = dis.readBoolean()
                    val isCompressedFlag = dis.readBoolean()
                    var payload = readByteArray(dis)
                    Log.d(TAG, "UserMessage: Raw payload ${payload.size}B, isPrivate:$isPrivate, isCompressed:$isCompressedFlag for channel '$channel'")

                    if (isPrivate) {
                        if (sharedSecretKey == null) {
                            Log.e(TAG, "UserMessage: Cannot decrypt private message for channel '$channel'. Shared secret key is NULL.")
                            return null
                        }
                        if (payload.size < GCM_IV_LENGTH_BYTES) {
                            Log.e(TAG, "UserMessage: Private payload for channel '$channel' too short to contain IV. Size: ${payload.size}")
                            return null
                        }
                        val iv = payload.copyOfRange(0, GCM_IV_LENGTH_BYTES)
                        val ciphertextWithTag = payload.copyOfRange(GCM_IV_LENGTH_BYTES, payload.size)
                        Log.d(TAG, "UserMessage: Decrypting private message for channel '$channel'. IV:${iv.size}B, Cipher+Tag:${ciphertextWithTag.size}B")

                        val decryptedPaddedPayload = encryptionService.decryptAES_GCM(ciphertextWithTag, sharedSecretKey, iv, null)
                        if (decryptedPaddedPayload == null) {
                            Log.e(TAG, "UserMessage: Failed to decrypt private message for channel '$channel'.")
                            return null
                        }
                        Log.d(TAG, "UserMessage: Decrypted private message for channel '$channel' to ${decryptedPaddedPayload.size}B (padded).")
                        payload = PaddingUtil.removePKCS7Padding(decryptedPaddedPayload)
                        if (payload == null) {
                            Log.e(TAG, "UserMessage: Failed to unpad decrypted private message (PKCS7) for channel '$channel'.")
                            return null
                        }
                         Log.d(TAG, "UserMessage: Unpadded private message for channel '$channel' to ${payload.size}B.")
                    }

                    var actualText: String
                    if (isCompressedFlag) {
                        Log.d(TAG, "UserMessage: Decompressing payload of size ${payload.size} for channel '$channel'")
                        val decompressedPayload = CompressionUtil.decompress(payload, payload.size * 10 + 1024) // Heuristic for output buffer
                        if (decompressedPayload == null) {
                            Log.e(TAG, "UserMessage: Failed to decompress message for channel '$channel'. Using raw payload as text (potential error).")
                            actualText = payload.toString(Charsets.UTF_8)
                        } else {
                            actualText = decompressedPayload.toString(Charsets.UTF_8)
                            Log.i(TAG, "UserMessage: Decompressed payload for channel '$channel' to ${actualText.toByteArray().size}B text.")
                        }
                    } else {
                        actualText = payload.toString(Charsets.UTF_8)
                    }
                    BitchatMessage.UserMessage(channel, senderDisplayName, actualText, isPrivate, isCompressedFlag)
                }
                0x05.toByte() -> BitchatMessage.Fragment(UUID.fromString(dis.readUTF()), dis.readInt(), dis.readInt(), readByteArray(dis))
                0x06.toByte() -> BitchatMessage.Ack(UUID.fromString(dis.readUTF()))
                0x07.toByte() -> {
                    val channel = dis.readUTF()
                    val hasPass = dis.readBoolean()
                    BitchatMessage.ChannelJoinRequest(channel, if(hasPass) readByteArray(dis) else null)
                }
                0x08.toByte() -> {
                    val channel = dis.readUTF()
                    val success = dis.readBoolean()
                    val hasError = dis.readBoolean()
                    BitchatMessage.ChannelJoinResponse(channel, success, if(hasError) dis.readUTF() else null)
                }
                0x09.toByte() -> {
                    val channel = dis.readUTF()
                    val hasPass = dis.readBoolean()
                    BitchatMessage.ChannelCreateRequest(channel, if(hasPass) readByteArray(dis) else null)
                }
                0x0A.toByte() -> {
                     val channel = dis.readUTF()
                    val success = dis.readBoolean()
                    val hasError = dis.readBoolean()
                    BitchatMessage.ChannelCreateResponse(channel, success, if(hasError) dis.readUTF() else null)
                }
                0x0B.toByte() -> { // StateSyncRequest
                    val hasTimestamp = dis.readBoolean()
                    val timestamp = if (hasTimestamp) dis.readLong() else null
                    val hasChannelIds = dis.readBoolean()
                    val channelIds = if (hasChannelIds) {
                        val count = dis.readInt()
                        List(count) { dis.readUTF() }
                    } else null
                    BitchatMessage.StateSyncRequest(timestamp, channelIds)
                }
                0x0C.toByte() -> { // StateSyncResponse
                    val forPeerId = dis.readUTF()
                    val hasMessages = dis.readBoolean()
                    // Actual deserialization of lists of packets/channelInfos would be complex here.
                    // This is a placeholder for the structure.
                    val messages = if (hasMessages) emptyList<BitchatPacket>() else null // Placeholder
                    val hasChannelUpdates = dis.readBoolean()
                    val channelUpdates = if (hasChannelUpdates) emptyList<ChannelInfo>() else null // Placeholder
                    BitchatMessage.StateSyncResponse(forPeerId, messages, channelUpdates)
                }
                else -> {
                    Log.w(TAG, "deserializeMessage: Unknown message type byte: 0x${typeByte.toString(16)}")
                    null
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "deserializeMessage: IOException (TypeByte: 0x${typeByte.toString(16)}): ${e.message}", e)
            return null
        } catch (e: IllegalArgumentException) {
             Log.e(TAG, "deserializeMessage: IllegalArgumentException (e.g. invalid UUID string): ${e.message}", e)
            return null
        } catch (e: Exception) {
            Log.e(TAG, "deserializeMessage: Unexpected error: ${e.message}", e)
            return null
        }
    }

    // --- Helper functions for DataInputStream/DataOutputStream ---
    private fun writeByteArray(dos: DataOutputStream, value: ByteArray) {
        dos.writeInt(value.size)
        dos.write(value)
    }

    private fun readByteArray(dis: DataInputStream): ByteArray {
        val length = dis.readInt()
        if (length < 0) throw IOException("Invalid array length: $length")
        if (length > 10 * 1024 * 1024) { // 10MB sanity limit
            throw IOException("Array length $length exceeds safety limit.")
        }
        val bytes = ByteArray(length)
        dis.readFully(bytes)
        return bytes
    }
}
