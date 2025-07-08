package com.example.bitchat.viewmodel

import android.app.Application
import android.bluetooth.BluetoothDevice
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.bitchat.models.BitchatMessage
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.services.EncryptionService
import com.example.bitchat.services.MessageMetadataService
// Import other necessary services and models like BluetoothDevice if/when used for peer list
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.UUID

// Simple data class for UI representation of a message
data class UiMessage(
    val id: UUID = UUID.randomUUID(),
    val senderName: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isFromCurrentUser: Boolean,
    val channel: String
)

class ChatViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "ChatViewModel"
    }

    // --- Dependencies (These would ideally be injected, e.g., with Hilt/Koin) ---
    // For now, we might need to instantiate them or get them from the Application context if bound.
    // This is a simplified setup.
    private val dataStorageService = DataStorageService(application)
    private val encryptionService = EncryptionService()
    // BluetoothMeshService needs to be bound and retrieved, or passed directly. This is a placeholder.
    // lateinit var bluetoothMeshService: BluetoothMeshService
    // lateinit var messageMetadataService: MessageMetadataService


    // --- UI State ---
    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    val messages: StateFlow<List<UiMessage>> = _messages.asStateFlow()

    private val _currentChannel = MutableStateFlow("#general") // Default channel
    val currentChannel: StateFlow<String> = _currentChannel.asStateFlow()

    private val _inputText = MutableStateFlow("")
    val inputText: StateFlow<String> = _inputText.asStateFlow()

    private val _displayName = MutableStateFlow("User")
    val displayName: StateFlow<String> = _displayName.asStateFlow()

    private val _isBluetoothReady = MutableStateFlow(false) // Placeholder
    val isBluetoothReady: StateFlow<Boolean> = _isBluetoothReady.asStateFlow()

    private val _connectedPeers = MutableStateFlow<List<BluetoothDevice>>(emptyList()) // Placeholder
    val connectedPeers: StateFlow<List<BluetoothDevice>> = _connectedPeers.asStateFlow()

    private var ephemeralPeerId: String = UUID.randomUUID().toString() // User's own ephemeral ID

    init {
        loadDisplayName()
        generateEphemeralId()
        // TODO: Observe BluetoothMeshService states (scanning, advertising, connected devices, received messages)
        // TODO: Observe MessageMetadataService for status updates
    }

    private fun loadDisplayName() {
        viewModelScope.launch {
            dataStorageService.displayNameFlow.collect { name ->
                _displayName.value = name ?: "User-${UUID.randomUUID().toString().substring(0, 4)}"
                if (name == null) {
                    // Save the generated default name
                    dataStorageService.saveDisplayName(_displayName.value)
                }
            }
        }
    }

    private fun generateEphemeralId() {
        viewModelScope.launch {
            val storedId = dataStorageService.getUserEphemeralId()
            if (storedId != null) {
                ephemeralPeerId = storedId
            } else {
                ephemeralPeerId = UUID.randomUUID().toString()
                dataStorageService.saveUserEphemeralId(ephemeralPeerId)
            }
            Log.d(TAG, "Current ephemeral peer ID: $ephemeralPeerId")
        }
    }

    fun onInputTextChanged(newText: String) {
        _inputText.value = newText
    }

    fun sendMessage(text: String) {
        if (text.isBlank()) return

        val currentText = text.trim()
        _inputText.value = "" // Clear input field

        if (currentText.startsWith("/")) {
            handleCommand(currentText)
        } else {
            val userMessage = BitchatMessage.UserMessage(
                channel = _currentChannel.value,
                senderDisplayName = _displayName.value,
                text = currentText,
                isPrivate = false, // TODO: Implement private message toggle/logic
                isCompressed = true // TODO: Make this configurable or dynamic
            )
            val packet = BitchatPacket(
                sourceId = ephemeralPeerId, // Use our ephemeral ID
                message = userMessage,
                ttl = 3 // Example TTL
            )

            // Add to UI immediately (optimistic update)
            addMessageToUi(packet, true)

            // TODO: Get target device address(es) from BluetoothMeshService or connection manager
            // For now, this is a placeholder for sending logic.
            // bluetoothMeshService.sendPacket(packet, null) // null for broadcast/mesh logic
            // messageMetadataService.trackNewOutgoingMessage(packet, targetDeviceAddress)
            Log.i(TAG, "Attempting to send message: ${packet.message}")
            // Simulate message sending for UI testing
        }
    }

    private fun handleCommand(commandText: String) {
        val parts = commandText.drop(1).split(" ", limit = 2)
        val command = parts.firstOrNull()?.lowercase(Locale.getDefault())
        val args = if (parts.size > 1) parts[1] else null

        Log.d(TAG, "Handling command: /$command, Args: $args")

        when (command) {
            "join" -> args?.let { joinChannel(it.trim()) }
            "nick" -> args?.let { changeDisplayName(it.trim()) }
            "create" -> args?.let { createChannel(it.trim()) } // Assuming format: /create channelName [password]
            // TODO: Implement other commands: /leave, /msg <peer> <message>, /block, /unblock, /help, etc.
            else -> {
                 addMessageToUi(
                    sender = "System",
                    text = "Unknown command: $command",
                    isCurrentUserMsg = false,
                    channel = _currentChannel.value
                )
            }
        }
    }

    private fun joinChannel(channelName: String) {
        // TODO: Implement actual channel join logic (e.g., send ChannelJoinRequest)
        // For now, just switch the current channel locally
        _currentChannel.value = if (channelName.startsWith("#")) channelName else "#$channelName"
        addMessageToUi(
            sender = "System",
            text = "Joined channel: ${_currentChannel.value}",
            isCurrentUserMsg = false,
            channel = _currentChannel.value
        )
        // Clear messages from old channel? Or fetch messages for new channel?
        _messages.value = emptyList() // Simple clear for now
    }

    private fun createChannel(params: String) {
        // Example: /create mychannel password123
        // Example: /create mynewchannel
        val parts = params.split(" ", limit = 2)
        val channelName = if (parts.first().startsWith("#")) parts.first() else "#${parts.first()}"
        val password = if (parts.size > 1) parts[1] else null

        // TODO: Send ChannelCreateRequest to the mesh
        // val passwordHash = password?.let { encryptionService.deriveKeyFromPassword(it.toCharArray(), salt)?.encoded }
        // val request = BitchatMessage.ChannelCreateRequest(channelName, passwordHash)
        // ... send packet ...

        addMessageToUi(
            sender = "System",
            text = "Channel creation requested for: $channelName ${if (password != null) "with password" else "without password"}",
            isCurrentUserMsg = false,
            channel = _currentChannel.value // Or a system channel
        )
        // Optimistically join the channel or wait for ChannelCreateResponse
        joinChannel(channelName)
    }


    private fun changeDisplayName(newName: String) {
        if (newName.isNotBlank() && newName.length <= 30) {
            viewModelScope.launch {
                dataStorageService.saveDisplayName(newName)
                // _displayName.value = newName // Will be updated by the flow from dataStorageService
                 addMessageToUi(
                    sender = "System",
                    text = "Display name changed to: $newName",
                    isCurrentUserMsg = false,
                    channel = _currentChannel.value
                )
                // TODO: Send an Announce message with the new display name
                // val announceMsg = BitchatMessage.Announce(ephemeralPeerId, newName, /* get public key */)
                // ... send packet ...
            }
        } else {
             addMessageToUi(
                sender = "System",
                text = "Invalid display name. Max 30 chars, not blank.",
                isCurrentUserMsg = false,
                channel = _currentChannel.value
            )
        }
    }

    // Call this when a BitchatPacket is received by BluetoothMeshService
    fun onPacketReceived(packet: BitchatPacket) {
        Log.d(TAG, "Packet received in ViewModel: ${packet.id} from ${packet.sourceId}")
        // TODO: Decrypt if necessary (based on message type and shared secrets)
        // TODO: Decompress if necessary
        // TODO: Handle ACKs for our sent messages via MessageMetadataService
        // TODO: Send ACKs for received messages that require them

        when (val msg = packet.message) {
            is BitchatMessage.UserMessage -> {
                if (msg.channel == _currentChannel.value || _currentChannel.value == "#general" /* Adjust general channel logic */) {
                     addMessageToUi(packet, false)
                }
                // TODO: Store message if retention is implemented
                // TODO: Show notification if app is in background or channel is not active view
            }
            is BitchatMessage.Announce -> {
                // TODO: Update peer list, store public key
                Log.i(TAG, "Announce from ${msg.peerId} (${msg.displayName}) received.")
            }
            is BitchatMessage.KeyExchangeRequest -> {
                // TODO: Respond with KeyExchangeResponse using EncryptionService
                Log.i(TAG, "KeyExchangeRequest from ${msg.peerId} received.")
            }
            is BitchatMessage.KeyExchangeResponse -> {
                // TODO: Complete key agreement using EncryptionService, store shared secret
                Log.i(TAG, "KeyExchangeResponse from ${msg.peerId} received.")
            }
            is BitchatMessage.Ack -> {
                // messageMetadataService.onAckReceived(msg.messageId)
                Log.i(TAG, "ACK for ${msg.messageId} received.")
            }
            // Handle other message types
            else -> {
                Log.d(TAG, "Received unhandled message type: ${msg::class.simpleName}")
            }
        }
    }

    private fun addMessageToUi(packet: BitchatPacket, isCurrentUserMsg: Boolean) {
        val message = packet.message
        if (message is BitchatMessage.UserMessage) {
             val uiMsg = UiMessage(
                id = packet.id,
                senderName = message.senderDisplayName,
                text = message.text,
                timestamp = packet.timestamp,
                isFromCurrentUser = isCurrentUserMsg,
                channel = message.channel
            )
            _messages.value = _messages.value + uiMsg
        }
    }

    // Helper for system messages or direct UI additions
    private fun addMessageToUi(sender: String, text: String, isCurrentUserMsg: Boolean, channel: String) {
        val uiMsg = UiMessage(
            senderName = sender,
            text = text,
            isFromCurrentUser = isCurrentUserMsg,
            channel = channel
        )
        _messages.value = _messages.value + uiMsg
    }


    // To be called from Activity/Fragment when BluetoothMeshService is connected
    fun setBluetoothMeshService(service: BluetoothMeshService) {
        // this.bluetoothMeshService = service
        // this.messageMetadataService = MessageMetadataService(service) // Initialize with the service
        Log.d(TAG, "BluetoothMeshService instance set in ViewModel.")
        // Start observing flows from the service
        observeBluetoothServiceStates(service)
    }

    private fun observeBluetoothServiceStates(service: BluetoothMeshService) {
        service.isScanning
            .onEach { _isBluetoothReady.value = it || service.isAdvertising.value } // Example logic
            .launchIn(viewModelScope)

        service.isAdvertising
            .onEach { _isBluetoothReady.value = it || service.isScanning.value } // Example logic
            .launchIn(viewModelScope)

        service.connectedDevices
            .onEach { _connectedPeers.value = it }
            .launchIn(viewModelScope)

        // TODO: Observe received packets from BluetoothMeshService
        // service.receivedPacketsFlow.onEach { onPacketReceived(it) }.launchIn(viewModelScope)
    }

    override fun onCleared() {
        super.onCleared()
        // messageMetadataService.destroy() // Clean up if it holds resources/scopes
        Log.d(TAG, "ChatViewModel onCleared")
    }
}
