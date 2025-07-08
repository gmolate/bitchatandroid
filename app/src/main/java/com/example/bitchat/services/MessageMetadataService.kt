package com.example.bitchat.services

import android.util.Log
import com.example.bitchat.models.BitchatPacket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages metadata and lifecycle of messages, including delivery tracking,
 * retries, and potentially retention (though full retention/DB is out of scope for now).
 */
class MessageMetadataService(
    private val bluetoothMeshService: BluetoothMeshService // For sending/resending messages
) {
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    companion object {
        private const val TAG = "MessageMetadataService"
        private const val DEFAULT_RETRY_DELAY_MS = 5000L
        private const val MAX_RETRIES = 3
        private const val ACK_TIMEOUT_MS = 10000L // Time to wait for an ACK
    }

    // --- Delivery Tracking ---
    enum class MessageStatus { PENDING_SEND, SENT_AWAITING_ACK, DELIVERED, FAILED_NO_ACK, FAILED_TO_SEND }

    data class TrackedMessage(
        val packet: BitchatPacket,
        var status: MessageStatus,
        var retryCount: Int = 0,
        val submissionTime: Long = System.currentTimeMillis(),
        var lastAttemptTime: Long = 0L
    )

    private val outgoingMessages = ConcurrentHashMap<UUID, TrackedMessage>()

    // Flow to notify UI/ViewModel about message status updates
    private val _messageStatusUpdates = MutableSharedFlow<Pair<UUID, MessageStatus>>()
    val messageStatusUpdates = _messageStatusUpdates.asSharedFlow()


    fun trackNewOutgoingMessage(packet: BitchatPacket, targetDeviceAddress: String?) {
        if (outgoingMessages.containsKey(packet.id)) {
            Log.w(TAG, "Message ${packet.id} is already being tracked.")
            return
        }
        val trackedMsg = TrackedMessage(packet, MessageStatus.PENDING_SEND)
        outgoingMessages[packet.id] = trackedMsg
        Log.d(TAG, "Tracking new outgoing message: ${packet.id}")

        // Attempt to send immediately
        attemptSend(packet.id, targetDeviceAddress)
    }

    private fun attemptSend(messageId: UUID, targetDeviceAddress: String?) {
        val trackedMsg = outgoingMessages[messageId] ?: return

        // This is a simplified send. In reality, BluetoothMeshService would handle
        // selecting appropriate peers if targetDeviceAddress is null (for broadcast/multicast).
        // For now, assume direct send if address is provided.
        if (targetDeviceAddress != null) {
            Log.d(TAG, "Attempting to send message ${messageId} to $targetDeviceAddress (Attempt ${trackedMsg.retryCount + 1})")
            // TODO: Serialize packet.message to get payload for BluetoothMeshService.sendMessage
            // This is a simplified call, actual implementation would need the serialized message bytes.
            // bluetoothMeshService.sendMessage(targetDeviceAddress, packet.message.toString()) // Placeholder

            // For now, simulate sending and move to SENT_AWAITING_ACK
            // In real implementation, BluetoothMeshService would confirm send initiation
             serviceScope.launch {
                trackedMsg.status = MessageStatus.SENT_AWAITING_ACK
                trackedMsg.lastAttemptTime = System.currentTimeMillis()
                _messageStatusUpdates.emit(messageId to trackedMsg.status)
                Log.d(TAG, "Message ${messageId} status updated to SENT_AWAITING_ACK.")
                startAckTimer(messageId, targetDeviceAddress)
            }
        } else {
            // TODO: Handle broadcast/multicast logic if targetDeviceAddress is null
            Log.w(TAG, "Broadcast/multicast send not yet implemented for message ${messageId}")
            trackedMsg.status = MessageStatus.FAILED_TO_SEND // Or a specific status for no route
            serviceScope.launch { _messageStatusUpdates.emit(messageId to trackedMsg.status) }
        }
    }

    private fun startAckTimer(messageId: UUID, targetDeviceAddress: String?) {
        serviceScope.launch {
            delay(ACK_TIMEOUT_MS)
            val trackedMsg = outgoingMessages[messageId]
            if (trackedMsg != null && trackedMsg.status == MessageStatus.SENT_AWAITING_ACK) {
                Log.w(TAG, "ACK timeout for message ${messageId}. Retrying if possible.")
                handleAckTimeout(messageId, targetDeviceAddress)
            }
        }
    }

    private fun handleAckTimeout(messageId: UUID, targetDeviceAddress: String?) {
        val trackedMsg = outgoingMessages[messageId] ?: return

        if (trackedMsg.retryCount < MAX_RETRIES) {
            trackedMsg.retryCount++
            Log.d(TAG, "Retrying message ${messageId} (Attempt ${trackedMsg.retryCount + 1})")
            attemptSend(messageId, targetDeviceAddress)
        } else {
            Log.e(TAG, "Message ${messageId} failed after $MAX_RETRIES retries (no ACK).")
            trackedMsg.status = MessageStatus.FAILED_NO_ACK
            serviceScope.launch { _messageStatusUpdates.emit(messageId to trackedMsg.status) }
            // Potentially remove from tracking or mark for later cleanup
        }
    }

    fun onAckReceived(messageId: UUID) {
        val trackedMsg = outgoingMessages[messageId]
        if (trackedMsg != null) {
            if (trackedMsg.status == MessageStatus.SENT_AWAITING_ACK || trackedMsg.status == MessageStatus.PENDING_SEND) {
                trackedMsg.status = MessageStatus.DELIVERED
                serviceScope.launch { _messageStatusUpdates.emit(messageId to trackedMsg.status) }
                Log.i(TAG, "ACK received for message ${messageId}. Status: DELIVERED.")
                // outgoingMessages.remove(messageId) // Or keep for a while for UI purposes
            } else {
                Log.w(TAG, "ACK received for message ${messageId}, but its status was ${trackedMsg.status}. Ignoring.")
            }
        } else {
            Log.w(TAG, "Received ACK for untracked or already processed message ID: $messageId")
        }
    }

    fun onSendFailed(messageId: UUID, isPermanentFailure: Boolean = false) {
        val trackedMsg = outgoingMessages[messageId] ?: return
        Log.e(TAG, "Send failed for message ${messageId}.")
        if (isPermanentFailure || trackedMsg.retryCount >= MAX_RETRIES) {
            trackedMsg.status = MessageStatus.FAILED_TO_SEND
        } else {
            // Could implement a more nuanced retry strategy here, e.g. based on error type
            handleAckTimeout(messageId, null) // Reuse timeout logic for retrying
        }
        serviceScope.launch { _messageStatusUpdates.emit(messageId to trackedMsg.status) }
    }


    // --- Message Retention (Placeholder) ---
    // In a real app, this would involve a database or persistent cache.
    // For now, we are just tracking outgoing messages in memory.
    // Incoming messages would be handled by ChatViewModel and displayed.
    fun cleanupOldMessages() {
        val now = System.currentTimeMillis()
        val messagesToRemove = mutableListOf<UUID>()
        outgoingMessages.forEach { (id, trackedMsg) ->
            // Example: Remove completed or very old pending messages
            if (trackedMsg.status == MessageStatus.DELIVERED || trackedMsg.status == MessageStatus.FAILED_NO_ACK || trackedMsg.status == MessageStatus.FAILED_TO_SEND) {
                if (now - trackedMsg.submissionTime > 60 * 60 * 1000) { // 1 hour
                    messagesToRemove.add(id)
                }
            } else if (now - trackedMsg.submissionTime > 24 * 60 * 60 * 1000) { // 1 day for pending
                 messagesToRemove.add(id)
            }
        }
        messagesToRemove.forEach { outgoingMessages.remove(it) }
        if (messagesToRemove.isNotEmpty()) {
            Log.d(TAG, "Cleaned up ${messagesToRemove.size} old tracked messages.")
        }
    }

    fun getTrackedMessageStatus(messageId: UUID): MessageStatus? {
        return outgoingMessages[messageId]?.status
    }

    fun destroy() {
        serviceScope.cancel()
        outgoingMessages.clear()
        Log.d(TAG, "MessageMetadataService destroyed.")
    }
}
