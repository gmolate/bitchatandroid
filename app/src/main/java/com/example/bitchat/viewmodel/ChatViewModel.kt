package com.example.bitchat.viewmodel

import android.app.Application
import android.bluetooth.BluetoothDevice // Keep this import
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.bitchat.models.BitchatMessage
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.models.BinaryProtocol // Assuming BinaryProtocol is an object or class
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.services.EncryptionService
import com.example.bitchat.services.MessageMetadataService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.Locale // For lowercase
import java.util.UUID

/**
 * Represents a message object tailored for display in the UI.
 *
 * @property id Unique identifier for the message.
 * @property senderName Display name of the message sender.
 * @property text The content of the message.
 * @property timestamp Time when the message was sent/received (in milliseconds).
 * @property isFromCurrentUser True if the message was sent by the current user, false otherwise.
 * @property channel The channel to which this message belongs.
 */
data class UiMessage(
    val id: UUID = UUID.randomUUID(),
    val senderName: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isFromCurrentUser: Boolean,
    val channel: String
)

/**
 * ViewModel for the Chat screen.
 * Manages UI state, handles user interactions, and communicates with backend services.
 *
 * @param application The application context, used for AndroidViewModel.
 */
class ChatViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "ChatViewModel"
    }

    // --- Dependencies ---
    private val dataStorageService = DataStorageService(application)
    private val encryptionSvc = EncryptionService() // Renamed to avoid conflict if EncryptionService is also a class name

    private var bluetoothMeshService: BluetoothMeshService? = null
    private var messageMetadataService: MessageMetadataService? = null


    // --- UI State ---
    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    /** Flow of messages to be displayed in the current channel. */
    val messages: StateFlow<List<UiMessage>> = _messages.asStateFlow()

    private val _currentChannel = MutableStateFlow("#general")
    /** Flow representing the currently active chat channel. */
    val currentChannel: StateFlow<String> = _currentChannel.asStateFlow()

    private val _inputText = MutableStateFlow("")
    /** Flow representing the current text in the message input field. */
    val inputText: StateFlow<String> = _inputText.asStateFlow()

    private val _displayName = MutableStateFlow("User")
    /** Flow representing the current user's display name. */
    val displayName: StateFlow<String> = _displayName.asStateFlow()

    private val _isBluetoothReady = MutableStateFlow(false)
    /** Flow indicating if Bluetooth is initialized and ready for operations. */
    val isBluetoothReady: StateFlow<Boolean> = _isBluetoothReady.asStateFlow()

    private val _connectedPeers = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    /** Flow representing the list of currently connected Bluetooth peers. */
    val connectedPeers: StateFlow<List<BluetoothDevice>> = _connectedPeers.asStateFlow()

    private var ephemeralPeerId: String = UUID.randomUUID().toString()

    init {
        loadDisplayName()
        generateAndLoadEphemeralId()
    }

    private fun loadDisplayName() {
        viewModelScope.launch {
            dataStorageService.displayNameFlow.collect { name ->
                val newName = name ?: "User-${UUID.randomUUID().toString().substring(0, 4)}"
                _displayName.value = newName
                if (name == null) {
                    dataStorageService.saveDisplayName(newName)
                }
                Log.d(TAG, "Display name set to: $newName")
            }
        }
    }

    private fun generateAndLoadEphemeralId() {
        viewModelScope.launch {
            val storedId = dataStorageService.getUserEphemeralId()
            if (storedId != null) {
                ephemeralPeerId = storedId
                Log.d(TAG, "Loaded ephemeral peer ID: $ephemeralPeerId")
            } else {
                ephemeralPeerId = UUID.randomUUID().toString()
                dataStorageService.saveUserEphemeralId(ephemeralPeerId)
                Log.d(TAG, "Generated and saved new ephemeral peer ID: $ephemeralPeerId")
            }
        }
    }

    fun onInputTextChanged(newText: String) {
        _inputText.value = newText
    }

    fun sendMessage(text: String) {
        if (text.isBlank()) return

        val currentText = text.trim()
        _inputText.value = ""

        if (currentText.startsWith("/")) {
            handleCommand(currentText)
        } else {
            if (bluetoothMeshService == null || messageMetadataService == null) {
                Log.e(TAG, "Services not initialized. Cannot send message: '$currentText'")
                addMessageToUi("System", "Error: Services not ready. Cannot send message.", false, _currentChannel.value)
                return
            }

            val userMessage = BitchatMessage.UserMessage(
                channel = _currentChannel.value,
                senderDisplayName = _displayName.value,
                text = currentText,
                isPrivate = false,
                isCompressed = true
            )
            val packetId = UUID.randomUUID()
            val packet = BitchatPacket(
                id = packetId,
                sourceId = ephemeralPeerId,
                message = userMessage,
                ttl = 3
            )

            addMessageToUi(packet, true)

            viewModelScope.launch(Dispatchers.IO) {
                val serializedMessage = BinaryProtocol.serializeMessage(userMessage, encryptionSvc, null) // Pass encryptionSvc
                if (serializedMessage == null) {
                    Log.e(TAG, "Failed to serialize UserMessage for packet ${packet.id}")
                    messageMetadataService?.onSendFailed(packet.id, true)
                    return@launch
                }

                // TODO: Sign the packet (dataToSign needs serialized message)
                // val dataToSign = packet.dataToSign(serializedMessage)
                // val identityPrivateKey = dataStorageService.getIdentityPrivateKey()
                // if (identityPrivateKey == null) { ... handle error ... return@launch }
                // packet.signature = encryptionSvc.signEd25519(dataToSign, identityPrivateKey)
                // if (packet.signature == null) { ... handle error ... }

                Log.d(TAG, "Requesting BluetoothMeshService to send serialized message for packet ${packet.id}")
                bluetoothMeshService?.sendDataToPeers(serializedMessage, packet)
                messageMetadataService?.trackNewOutgoingMessage(packet, null)
            }
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
            "create" -> args?.let { createChannel(it.trim()) }
            "id" -> showMyId()
            else -> {
                 addMessageToUi(
                    senderName = "System",
                    text = "Unknown command: $command",
                    isFromCurrentUser = false,
                    channel = _currentChannel.value
                )
            }
        }
    }

    private fun showMyId() {
        addMessageToUi(
            senderName = "System",
            text = "Your current ephemeral ID: $ephemeralPeerId\nYour display name: ${_displayName.value}",
            isFromCurrentUser = false,
            channel = _currentChannel.value
        )
    }

    private fun joinChannel(channelName: String) {
        val targetChannel = if (channelName.startsWith("#")) channelName else "#$channelName"
        _currentChannel.value = targetChannel
        addMessageToUi(
            senderName = "System",
            text = "Joined channel: $targetChannel (Local change for now)",
            isFromCurrentUser = false,
            channel = targetChannel
        )
        _messages.value = emptyList()
        Log.i(TAG, "Switched to channel: $targetChannel")
    }

    private fun createChannel(params: String) {
        val parts = params.split(" ", limit = 2)
        val channelName = if (parts.first().startsWith("#")) parts.first() else "#${parts.first()}"
        val password = if (parts.size > 1) parts[1] else null

        addMessageToUi(
            senderName = "System",
            text = "Channel creation requested for: $channelName ${if (password != null) "with password (not implemented)" else "without password"}. (Local log)",
            isFromCurrentUser = false,
            channel = _currentChannel.value
        )
        joinChannel(channelName)
    }

    private fun changeDisplayName(newName: String) {
        if (newName.isNotBlank() && newName.length <= 30) {
            viewModelScope.launch {
                dataStorageService.saveDisplayName(newName)
                 addMessageToUi(
                    senderName = "System",
                    text = "Display name will be updated to: $newName (Restart or Announce needed)",
                    isFromCurrentUser = false,
                    channel = _currentChannel.value
                )
                Log.i(TAG, "Display name change requested to: $newName")
            }
        } else {
             addMessageToUi(
                senderName = "System",
                text = "Invalid display name. Must be 1-30 characters.",
                isFromCurrentUser = false,
                channel = _currentChannel.value
            )
        }
    }

    fun onPacketReceived(packet: BitchatPacket) {
        Log.d(TAG, "Packet received in ViewModel: ID=${packet.id}, From=${packet.sourceId}, Type=${packet.message::class.simpleName}")

        when (val msg = packet.message) {
            is BitchatMessage.UserMessage -> {
                if (msg.channel == _currentChannel.value || _currentChannel.value == "#general") {
                     addMessageToUi(packet, false)
                }
            }
            is BitchatMessage.Announce -> {
                Log.i(TAG, "Announce from ${msg.peerId} (${msg.displayName}) with pubkey: ${msg.publicKey.size} bytes.")
                 addMessageToUi("System", "Peer Announcement: ${msg.displayName} (${msg.peerId.take(8)}...)", false, _currentChannel.value)
            }
            is BitchatMessage.KeyExchangeRequest -> {
                Log.i(TAG, "KeyExchangeRequest from ${msg.peerId} with their ephemeral pubkey.")
                addMessageToUi("System", "Key Exchange Request from ${msg.peerId.take(8)}...", false, _currentChannel.value)
            }
            is BitchatMessage.KeyExchangeResponse -> {
                Log.i(TAG, "KeyExchangeResponse from ${msg.peerId} with their ephemeral pubkey.")
                 addMessageToUi("System", "Key Exchange Response from ${msg.peerId.take(8)}...", false, _currentChannel.value)
            }
            is BitchatMessage.Ack -> {
                messageMetadataService?.onAckReceived(msg.messageId)
                Log.i(TAG, "ACK received for our message: ${msg.messageId}")
            }
            is BitchatMessage.ChannelJoinResponse -> {
                val status = if (msg.success) "Successfully joined" else "Failed to join"
                val errorMsg = if (msg.error != null) " Error: ${msg.error}" else ""
                addMessageToUi("System", "$status channel ${msg.channel}.$errorMsg", false, msg.channel)
                if (msg.success) _currentChannel.value = msg.channel
            }
            else -> {
                Log.d(TAG, "Received unhandled BitchatMessage type: ${msg::class.simpleName}")
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
            _messages.value = (_messages.value + uiMsg).sortedBy { it.timestamp }
        }
    }

    private fun addMessageToUi(senderName: String, text: String, isFromCurrentUser: Boolean, channel: String) {
        val uiMsg = UiMessage(
            senderName = senderName,
            text = text,
            isFromCurrentUser = isFromCurrentUser,
            channel = channel
        )
        _messages.value = (_messages.value + uiMsg).sortedBy { it.timestamp }
    }

    fun setBluetoothServices(service: BluetoothMeshService) {
        this.bluetoothMeshService = service
        this.messageMetadataService = MessageMetadataService(service)
        Log.d(TAG, "BluetoothMeshService and MessageMetadataService instances set in ViewModel.")
        observeBluetoothServiceStates(service)
        observeMessageStatusUpdates()
    }

    private fun observeBluetoothServiceStates(service: BluetoothMeshService) {
        service.isScanning
            .onEach { scanning ->
                val currentAdvertisingState = bluetoothMeshService?.isAdvertising?.value ?: false
                _isBluetoothReady.value = scanning || currentAdvertisingState
            }
            .launchIn(viewModelScope)

        service.isAdvertising
            .onEach { advertising ->
                val currentScanningState = bluetoothMeshService?.isScanning?.value ?: false
                _isBluetoothReady.value = advertising || currentScanningState
            }
            .launchIn(viewModelScope)

        service.connectedDevices
            .onEach { peers -> _connectedPeers.value = peers }
            .launchIn(viewModelScope)

        service.processedReceivedPacketsFlow
            .onEach { packet -> onPacketReceived(packet) }
            .launchIn(viewModelScope)
        Log.d(TAG, "Started observing Bluetooth service states and received packets.")
    }

    private fun observeMessageStatusUpdates() {
        messageMetadataService?.messageStatusUpdates?.onEach { (messageId, status) ->
            Log.d(TAG, "Message $messageId status update: $status")
            if (status == MessageMetadataService.MessageStatus.FAILED_NO_ACK || status == MessageMetadataService.MessageStatus.FAILED_TO_SEND) {
                _messages.update { currentMessages ->
                    currentMessages.map {
                        if (it.id == messageId) it.copy(text = "${it.text} (Failed to send)") else it
                    }.sortedBy { it.timestamp }
                }
            }
        }?.launchIn(viewModelScope)
    }

    override fun onCleared() {
        super.onCleared()
        messageMetadataService?.destroy()
        Log.d(TAG, "ChatViewModel onCleared.")
    }
}
