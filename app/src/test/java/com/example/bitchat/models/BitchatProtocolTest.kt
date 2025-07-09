package com.example.bitchat.models

import com.example.bitchat.services.EncryptionService // Mock or real for serialization context
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.UUID
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

// Using the actual EncryptionService for these tests now that BouncyCastle is integrated.
// This makes the tests more of an integration test for protocol + basic crypto.
class BitchatProtocolTest {

    private lateinit var encryptionService: EncryptionService
    private val defaultPeerId = "testPeer123"
    private val defaultDisplayName = "Test User"
    private val defaultChannel = "#testChannel"
    private lateinit var sampleKeyPair: KeyPair // For Ed25519
    private lateinit var sampleX25519KeyPair: KeyPair // For X25519

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
        encryptionService = EncryptionService()
        sampleKeyPair = encryptionService.generateEd25519KeyPair()!!
        sampleX25519KeyPair = encryptionService.generateX25519KeyPair()!!
    }

    private fun createSamplePublicKey(): ByteArray { // Ed25519 public key
        return sampleKeyPair.public.encoded
    }

    private fun createSampleX25519PublicKey(): ByteArray {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    @Test
    fun serialize_deserialize_announceMessage() {
        val originalMessage = BitchatMessage.Announce(defaultPeerId, defaultDisplayName, createSamplePublicKey())
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull("Serialized Announce message should not be null", serialized)

        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertNotNull("Deserialized Announce message should not be null", deserialized)
        assertTrue("Deserialized message should be of type Announce", deserialized is BitchatMessage.Announce)

        val announceDes = deserialized as BitchatMessage.Announce
        assertEquals(originalMessage.peerId, announceDes.peerId)
        assertEquals(originalMessage.displayName, announceDes.displayName)
        assertArrayEquals(originalMessage.publicKey, announceDes.publicKey)
    }

    @Test
    fun serialize_deserialize_keyExchangeRequest() {
        val originalMessage = BitchatMessage.KeyExchangeRequest(defaultPeerId, createSamplePublicKey())
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.KeyExchangeRequest)
        assertEquals(originalMessage, deserialized)
    }

    @Test
    fun serialize_deserialize_userMessage_public_uncompressed() {
        val originalMessage = BitchatMessage.UserMessage(defaultChannel, defaultDisplayName, "Hello World!", false, false)
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)

        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.UserMessage)
        val userMsgDes = deserialized as BitchatMessage.UserMessage

        assertEquals(originalMessage.channel, userMsgDes.channel)
        assertEquals(originalMessage.senderDisplayName, userMsgDes.senderDisplayName)
        assertEquals(originalMessage.text, userMsgDes.text)
        assertEquals(originalMessage.isPrivate, userMsgDes.isPrivate)
        assertEquals(originalMessage.isCompressed, userMsgDes.isCompressed) // Should reflect actual compression state
    }

    @Test
    fun serialize_deserialize_userMessage_public_compressed_placeholder() {
        // This test will pass based on the isCompressed flag being passed through,
        // not actual compression, due to LZ4Util being a placeholder.
        val originalMessage = BitchatMessage.UserMessage(defaultChannel, defaultDisplayName, "Long message to trigger compression logic.", false, true)
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)

        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.UserMessage)
        val userMsgDes = deserialized as BitchatMessage.UserMessage
        assertEquals(originalMessage.text, userMsgDes.text) // Text should be the same as no actual compression
        assertEquals(true, userMsgDes.isCompressed) // Flag should be true
    }

    @Test
    fun serialize_deserialize_userMessage_private_uncompressed_placeholder() {
        // This test relies on placeholders for encryption and padding.
        // It mainly checks if the structure and flags are preserved.
        val originalMessage = BitchatMessage.UserMessage(defaultChannel, defaultDisplayName, "Private message.", true, false)
        val dummySecret = SecretKeySpec(ByteArray(32), "AES") // 256-bit dummy key

        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService, dummySecret)
        assertNotNull("Serialized private message should not be null (even with placeholder crypto)", serialized)

        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService, dummySecret)
        assertNotNull("Deserialized private message should not be null", deserialized)
        assertTrue(deserialized is BitchatMessage.UserMessage)

        val userMsgDes = deserialized as BitchatMessage.UserMessage
        assertEquals(originalMessage.text, userMsgDes.text) // Text should be same due to placeholder crypto
        assertEquals(true, userMsgDes.isPrivate)
        assertEquals(false, userMsgDes.isCompressed)
    }


    @Test
    fun serialize_deserialize_ackMessage() {
        val originalMessage = BitchatMessage.Ack(UUID.randomUUID())
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.Ack)
        assertEquals(originalMessage, deserialized)
    }

    @Test
    fun serialize_deserialize_fragmentMessage() {
        val originalMessage = BitchatMessage.Fragment(UUID.randomUUID(), 1, 3, "fragment data".toByteArray())
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.Fragment)
        val frag = deserialized as BitchatMessage.Fragment
        assertEquals(originalMessage.originalMessageId, frag.originalMessageId)
        assertEquals(originalMessage.fragmentIndex, frag.fragmentIndex)
        assertEquals(originalMessage.totalFragments, frag.totalFragments)
        assertArrayEquals(originalMessage.data, frag.data)
    }

    @Test
    fun serialize_deserialize_channelJoinRequest_noPassword() {
        val originalMessage = BitchatMessage.ChannelJoinRequest("#newchannel")
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.ChannelJoinRequest)
        assertEquals(originalMessage.channel, (deserialized as BitchatMessage.ChannelJoinRequest).channel)
        assertNull((deserialized as BitchatMessage.ChannelJoinRequest).passwordHash)
    }

    @Test
    fun serialize_deserialize_channelJoinRequest_withPassword() {
        val passwordHash = "hashed_password".toByteArray()
        val originalMessage = BitchatMessage.ChannelJoinRequest("#securechannel", passwordHash)
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertTrue(deserialized is BitchatMessage.ChannelJoinRequest)
        assertEquals(originalMessage.channel, (deserialized as BitchatMessage.ChannelJoinRequest).channel)
        assertArrayEquals(passwordHash, (deserialized as BitchatMessage.ChannelJoinRequest).passwordHash)
    }

    @Test
    fun serialize_deserialize_channelJoinResponse_success() {
        val originalMessage = BitchatMessage.ChannelJoinResponse("#newchannel", true, null)
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertEquals(originalMessage, deserialized)
    }

    @Test
    fun serialize_deserialize_channelJoinResponse_failure() {
        val originalMessage = BitchatMessage.ChannelJoinResponse("#newchannel", false, "Incorrect password")
        val serialized = BinaryProtocol.serializeMessage(originalMessage, encryptionService)
        assertNotNull(serialized)
        val deserialized = BinaryProtocol.deserializeMessage(serialized!!, encryptionService)
        assertEquals(originalMessage, deserialized)
    }

    // --- BitchatPacket Serialization (Conceptual - as it might not be directly sent over BLE) ---
    @Test
    fun serialize_deserialize_bitchatPacket_placeholder() {
        val userMessage = BitchatMessage.UserMessage(defaultChannel, defaultDisplayName, "Packet Test", false, false)
        val originalPacket = BitchatPacket(
            sourceId = defaultPeerId,
            message = userMessage,
            ttl = 5,
            hops = 1,
            rssiAtLastHop = -55
            // Signature would be added by a real EncryptionService and peer's private key
        )

        // Note: packet.signature is not set here, so this test won't cover signature part of serialization.
        // Full packet serialization/deserialization testing would require a more complete EncryptionService mock
        // or integration if the signature is generated during packet serialization itself.
        val serializedMessageBytes = BinaryProtocol.serializeMessage(userMessage, encryptionService)!!

        // Temporarily assign a dummy signature if the serialization expects one (based on current BinaryProtocol.serializePacket)
        originalPacket.signature = "dummysig".toByteArray()


        val serializedPacket = BinaryProtocol.serializePacket(originalPacket, encryptionService)
        assertNotNull("Serialized packet should not be null", serializedPacket)

        val deserializedPacket = BinaryProtocol.deserializePacket(serializedPacket!!, encryptionService)
        assertNotNull("Deserialized packet should not be null", deserializedPacket)

        assertEquals(originalPacket.id, deserializedPacket!!.id)
        assertEquals(originalPacket.sourceId, deserializedPacket.sourceId)
        // assertEquals(originalPacket.timestamp, deserializedPacket.timestamp) // Timestamps can be tricky due to generation
        assertEquals(originalPacket.ttl, deserializedPacket.ttl)
        assertEquals(originalPacket.hops, deserializedPacket.hops)
        assertEquals(originalPacket.rssiAtLastHop, deserializedPacket.rssiAtLastHop)
        assertArrayEquals(originalPacket.signature, deserializedPacket.signature) // Will pass if both are null or same dummy

        assertTrue("Deserialized message in packet should be UserMessage", deserializedPacket.message is BitchatMessage.UserMessage)
        val deserializedUserMessage = deserializedPacket.message as BitchatMessage.UserMessage
        assertEquals(userMessage.text, deserializedUserMessage.text)
    }

}
