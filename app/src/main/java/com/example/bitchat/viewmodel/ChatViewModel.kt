package com.example.bitchat.viewmodel

import android.app.Application
import android.bluetooth.BluetoothDevice // Keep this import
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.bitchat.data.MessageRepository
import com.example.bitchat.models.BitchatMessage
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.models.BinaryProtocol
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.services.EncryptionService
import com.example.bitchat.services.MessageMetadataService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.Locale // For lowercase
import java.util.UUID
import javax.crypto.spec.SecretKeySpec

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
    val id: UUID = UUID.randomUUID(), // Keep as UUID for internal consistency before persistence
    val senderName: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isFromCurrentUser: Boolean,
    val channel: String
)

/**
 * ViewModel for the Chat screen.
 * Manages UI state, handles user interactions, and communicates with backend services and repository.
 *
 * @param application The application context, used for AndroidViewModel.
 */
class ChatViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "ChatViewModel"
    }

    // --- Dependencies ---
    private val dataStorageService = DataStorageService(application)
    private val encryptionSvc = EncryptionService()
    private val messageRepository: MessageRepository = MessageRepository(dataStorageService) // Initialize repository

    private var bluetoothMeshService: BluetoothMeshService? = null
    private var messageMetadataService: MessageMetadataService? = null

    // TODO: Proper Shared Secret Management (this is a placeholder)
    // In a real app, this would be populated after successful key exchange with each peer.
    private val peerSharedSecrets = mutableMapOf<String, ByteArray>()


    // --- UI State ---
    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    /** Flow of messages to be displayed in the current channel, sorted by timestamp. */
    val messages: StateFlow<List<UiMessage>> = _messages.asStateFlow()

    private val _currentChannel = MutableStateFlow("#general")
    val currentChannel: StateFlow<String> = _currentChannel.asStateFlow()

    private val _inputText = MutableStateFlow("")
    val inputText: StateFlow<String> = _inputText.asStateFlow()

    private val _displayName = MutableStateFlow("User")
    val displayName: StateFlow<String> = _displayName.asStateFlow()

    private val _isBluetoothReady = MutableStateFlow(false)
    val isBluetoothReady: StateFlow<Boolean> = _isBluetoothReady.asStateFlow()

    private val _connectedPeers = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val connectedPeers: StateFlow<List<BluetoothDevice>> = _connectedPeers.asStateFlow()

    private val _isSendingMessage = MutableStateFlow(false)
    /** Flow indicating if a message is currently being sent. */
    val isSendingMessage: StateFlow<Boolean> = _isSendingMessage.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    /** Flow for emitting error messages to be displayed in the UI. */
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private var ephemeralPeerId: String = UUID.randomUUID().toString()

    init {
        loadDisplayName()
        generateAndLoadEphemeralId()
        observeCurrentChannelMessages() // Start observing messages for the initial channel
    }

    private fun loadDisplayName() {
        viewModelScope.launch {
            dataStorageService.displayNameFlow.firstOrNull()?.let { name ->
                _displayName.value = name
            } ?: run {
                val defaultName = "User-${UUID.randomUUID().toString().substring(0, 4)}"
                _displayName.value = defaultName
                dataStorageService.saveDisplayName(defaultName)
            }
            Log.d(TAG, "Display name set to: ${_displayName.value}")
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

    /**
     * Observes messages for the current channel from the repository.
     */
    private fun observeCurrentChannelMessages() {
        viewModelScope.launch {
            // Every time currentChannel changes, switch the observation.
            _currentChannel.flatMapLatest { channelName ->
                messageRepository.getMessagesForChannel(channelName)
            }.catch { e ->
                Log.e(TAG, "Error observing messages for ${_currentChannel.value}: ${e.message}", e)
                _errorMessage.value = "Error loading messages."
            }.collect { channelMessages ->
                Log.d(TAG, "Loaded ${channelMessages.size} messages for channel ${_currentChannel.value}")
                _messages.value = channelMessages // Already sorted by repository
            }
        }
    }


    fun onInputTextChanged(newText: String) {
        _inputText.value = newText
    }

    fun sendMessage(text: String) {
        if (text.isBlank() || _isSendingMessage.value) return

        val currentText = text.trim()
        _inputText.value = ""

        if (currentText.startsWith("/")) {
            handleCommand(currentText)
        } else {
            if (bluetoothMeshService == null || messageMetadataService == null) {
                Log.e(TAG, "Services not initialized. Cannot send message: '$currentText'")
                viewModelScope.launch { _errorMessage.value = "Error: Services not ready." }
                return
            }

            val isPrivateMessage = false // TODO: Determine this from UI/channel properties
            val shouldCompress = true   // TODO: Determine this (e.g., based on message size)

            val userMessage = BitchatMessage.UserMessage(
                channel = _currentChannel.value,
                senderDisplayName = _displayName.value,
                text = currentText,
                isPrivate = isPrivateMessage,
                isCompressed = shouldCompress
            )
            val packetId = UUID.randomUUID()
            var packet = BitchatPacket( // Make it a var to update signature
                id = packetId,
                sourceId = ephemeralPeerId,
                message = userMessage,
                ttl = 3 // TODO: Configurable TTL
            )

            // Optimistic UI update
            val optimisticUiMessage = UiMessage(
                id = packet.id,
                senderName = _displayName.value,
                text = currentText,
                timestamp = System.currentTimeMillis(), // Use current time for optimistic UI
                isFromCurrentUser = true,
                channel = _currentChannel.value
            )
            _messages.value = (_messages.value + optimisticUiMessage).sortedBy { it.timestamp }


            viewModelScope.launch(Dispatchers.IO) {
                _isSendingMessage.value = true
                var success = false
                try {
                    // TODO: Retrieve actual sharedSecret for the recipient/channel if message.isPrivate
                    // This requires key exchange to have happened and secrets to be stored.
                    val sharedSecretForEncryption: ByteArray? = if (isPrivateMessage) {
                        // getSharedSecretForPeer(destinationPeerId) or getSharedSecretForChannel(_currentChannel.value)
                        // For now, placeholder - this would cause encryption to fail or use a dummy key if not handled.
                        Log.w(TAG, "Private message sending attempted but shared secret retrieval is TODO.")
                        null
                    } else null

                    // 1. Serialize the BitchatMessage (includes compression and encryption if private)
                    val serializedMessagePayload = BinaryProtocol.serializeMessage(userMessage, encryptionSvc, sharedSecretForEncryption)

                    if (serializedMessagePayload == null) {
                        Log.e(TAG, "Failed to serialize UserMessage for packet ${packet.id}")
                        _errorMessage.value = "Error: Could not prepare message."
                        // No need to call messageMetadataService.onSendFailed, as it wasn't tracked yet
                        success = false
                        return@launch
                    }

                    // 2. Sign the packet
                    val dataToSign = packet.dataToSign(serializedMessagePayload)
                    val identityPrivateKey = dataStorageService.getIdentityPrivateKey()
                    if (identityPrivateKey == null) {
                        Log.e(TAG, "Cannot sign packet ${packet.id}: Identity private key not available.")
                        _errorMessage.value = "Error: Cannot sign message. Identity not set up."
                        success = false
                        return@launch
                    }
                    val signature = encryptionSvc.signEd25519(dataToSign, identityPrivateKey)
                    if (signature == null) {
                        Log.w(TAG, "Failed to sign packet ${packet.id}. Sending unsigned (or configure to fail).")
                        _errorMessage.value = "Warning: Could not sign message."
                        // Decide policy: for now, allow sending unsigned but log.
                    }
                    packet = packet.copy(signature = signature) // Update packet with signature

                    // 3. Create the final byte array of the *entire* BitchatPacket
                    val finalPacketBytes = BinaryProtocol.serializePacket(packet, encryptionSvc, sharedSecretForEncryption)
                    if (finalPacketBytes == null) {
                        Log.e(TAG, "Failed to serialize the final BitchatPacket ${packet.id}")
                        _errorMessage.value = "Error: Could not finalize message packet."
                        success = false
                        return@launch
                    }

                    // 4. Track and send via BluetoothMeshService
                    Log.d(TAG, "Requesting BluetoothMeshService to send ${finalPacketBytes.size} bytes for packet ${packet.id}")
                    messageMetadataService?.trackNewOutgoingMessage(packet, null) // Track *before* sending
                    bluetoothMeshService?.sendDataToPeers(finalPacketBytes, packet)
                    success = true // Assume sendDataToPeers initiates the send; actual success/failure handled by MessageMetadataService via callbacks

                    // 5. Persist after initiating send
                    messageRepository.saveMessage(_currentChannel.value, optimisticUiMessage.copy(id = packet.id, timestamp = packet.timestamp))


                } catch (e: Exception) {
                    Log.e(TAG, "Exception during sendMessage for packet ${packet.id}: ${e.message}", e)
                    _errorMessage.value = "Error sending message: ${e.localizedMessage}"
                    messageMetadataService?.onSendFailed(packet.id, true)
                    success = false
                } finally {
                    _isSendingMessage.value = false
                    if (!success && _messages.value.lastOrNull()?.id == optimisticUiMessage.id) { // If optimistic update was done and send failed early
                         _messages.update { msgs -> msgs.filterNot { it.id == optimisticUiMessage.id } }
                         addMessageToUi("System", "Failed to prepare/send: $currentText", false, _currentChannel.value)
                    }
                }
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
            "clear" -> clearCurrentChannelMessages()
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

    private fun clearCurrentChannelMessages() {
        viewModelScope.launch {
            messageRepository.clearMessagesForChannel(_currentChannel.value)
            // UI will update automatically due to observing the flow from repository
            addMessageToUi("System", "Messages for ${_currentChannel.value} cleared.", false, _currentChannel.value)
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
        if (_currentChannel.value == targetChannel) {
            Log.d(TAG, "Already in channel: $targetChannel")
            return
        }

        Log.i(TAG, "Joining channel: $targetChannel")
        // TODO: Implement actual channel join logic via BluetoothMeshService.
        // For now, local optimistic switch:
        _currentChannel.value = targetChannel // This will trigger observeCurrentChannelMessages
        addMessageToUi("System", "Switched to channel: $targetChannel", false, targetChannel)
    }

    private fun createChannel(params: String) {
        val parts = params.split(" ", limit = 2)
        val channelName = if (parts.first().startsWith("#")) parts.first() else "#${parts.first()}"
        val password = if (parts.size > 1) parts[1] else null

        // TODO: Implement actual channel creation logic via BluetoothMeshService.
        addMessageToUi(
            senderName = "System",
            text = "Channel creation requested for: $channelName ${if (password != null) "with password" else ""}. (Placeholder)",
            isFromCurrentUser = false,
            channel = _currentChannel.value
        )
    }

    private fun changeDisplayName(newName: String) {
        if (newName.isNotBlank() && newName.length <= 30) {
            viewModelScope.launch {
                dataStorageService.saveDisplayName(newName) // _displayName will update via its collector
                 addMessageToUi(
                    senderName = "System",
                    text = "Display name will be updated to: $newName (Announce needed for mesh propagation)",
                    isFromCurrentUser = false,
                    channel = _currentChannel.value
                )
                // TODO: Send an Announce message with the new display name and public key
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
        Log.d(TAG, "Processed Packet received in ViewModel: ID=${packet.id}, From=${packet.sourceId}, Type=${packet.message::class.simpleName}")

        viewModelScope.launch(Dispatchers.IO) {
            // TODO: Signature Verification if not already done in BinaryProtocol.deserializePacket
            // Requires sender's public key.

            when (val msg = packet.message) {
                is BitchatMessage.UserMessage -> {
                    Log.i(TAG, "Processing UserMessage from ${msg.senderDisplayName} in #${msg.channel}: ${msg.text.take(50)}...")
                    val uiMsg = UiMessage(
                        id = packet.id,
                        senderName = msg.senderDisplayName,
                        text = msg.text,
                        timestamp = packet.timestamp,
                        isFromCurrentUser = (packet.sourceId == ephemeralPeerId),
                        channel = msg.channel
                    )
                    messageRepository.saveMessage(msg.channel, uiMsg) // Persist
                    // UI will update via the Flow from messageRepository.getMessagesForChannel for the active channel.

                    // TODO: Send ACK if protocol requires it for this message type.
                    // TODO: Show notification if app is in background AND message is not for current active channel.
                }
                is BitchatMessage.Announce -> {
                    Log.i(TAG, "Announce from ${msg.peerId} (${msg.displayName}). PK size: ${msg.publicKey.size}")
                    // TODO: Store peer info (peerId, displayName, publicKey)
                    addMessageToUi("System", "Peer Announcement: ${msg.displayName} (${msg.peerId.take(8)}...)", false, _currentChannel.value)
                }
                is BitchatMessage.KeyExchangeRequest -> {
                    Log.i(TAG, "KeyExchangeRequest from ${msg.peerId}")
                    // TODO: Key exchange logic
                    addMessageToUi("System", "Key Exchange Request from ${msg.peerId.take(8)}... (Processing TODO)", false, _currentChannel.value)
                }
                is BitchatMessage.KeyExchangeResponse -> {
                    Log.i(TAG, "KeyExchangeResponse from ${msg.peerId}")
                    // TODO: Key exchange logic
                     addMessageToUi("System", "Key Exchange Response from ${msg.peerId.take(8)}... (Processing TODO)", false, _currentChannel.value)
                }
                is BitchatMessage.Ack -> {
                    Log.i(TAG, "ACK received for our message: ${msg.messageId}")
                    messageMetadataService?.onAckReceived(msg.messageId)
                }
                is BitchatMessage.ChannelJoinResponse -> {
                    val statusMsg = if (msg.success) "Successfully joined" else "Failed to join"
                    val errorDetail = if (msg.error != null) " Error: ${msg.error}" else ""
                    addMessageToUi("System", "$statusMsg channel ${msg.channel}.$errorDetail", false, msg.channel)
                    if (msg.success && _currentChannel.value != msg.channel) {
                        _currentChannel.value = msg.channel // This will trigger reloading messages for the new channel
                    } else if (!msg.success) {
                        _errorMessage.value = "Failed to join ${msg.channel}: ${msg.error ?: "Unknown reason"}"
                    }
                }
                is BitchatMessage.ChannelCreateResponse -> {
                     val statusMsg = if (msg.success) "Channel '${msg.channel}' created successfully." else "Failed to create channel '${msg.channel}'."
                    val errorDetail = if (msg.error != null) " Error: ${msg.error}" else ""
                    addMessageToUi("System", "$statusMsg$errorDetail", false, _currentChannel.value)
                    // if (msg.success) { dataStorageService.addKnownChannel(msg.channel, hasPassword?) }
                }
                else -> {
                    Log.d(TAG, "Received unhandled BitchatMessage type in onPacketReceived: ${msg::class.simpleName}")
                }
            }
        }
    }

    // Optimistic UI update for sent messages (before persistence confirmation)
    private fun addMessageToUi(packet: BitchatPacket, isCurrentUserMsg: Boolean) {
        val message = packet.message
        if (message is BitchatMessage.UserMessage) {
             val uiMsg = UiMessage(
                id = packet.id,
                senderName = message.senderDisplayName,
                text = message.text,
                timestamp = packet.timestamp, // Use packet timestamp for consistency
                isFromCurrentUser = isCurrentUserMsg,
                channel = message.channel
            )
            _messages.update { currentList -> (currentList + uiMsg).sortedBy { it.timestamp } }
        }
    }

    // Helper for system messages or direct UI additions not tied to a BitchatPacket
    private fun addMessageToUi(senderName: String, text: String, isFromCurrentUser: Boolean, channel: String) {
        val uiMsg = UiMessage(
            senderName = senderName,
            text = text,
            timestamp = System.currentTimeMillis(), // System messages get current time
            isFromCurrentUser = isFromCurrentUser,
            channel = channel
        )
         _messages.update { currentList -> (currentList + uiMsg).sortedBy { it.timestamp } }
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
            // Update UI based on message status (e.g., show delivery ticks or failure notice)
            _messages.update { currentMessages ->
                currentMessages.map { uiMsg ->
                    if (uiMsg.id == messageId) {
                        when (status) {
                            MessageMetadataService.MessageStatus.FAILED_NO_ACK,
                            MessageMetadataService.MessageStatus.FAILED_TO_SEND -> uiMsg.copy(text = "${uiMsg.text} (Failed)") // Simple failure indication
                            MessageMetadataService.MessageStatus.DELIVERED -> uiMsg.copy(text = "${uiMsg.text} (Delivered)") // Simple delivered indication
                            else -> uiMsg // No change for PENDING_SEND or SENT_AWAITING_ACK for this example
                        }
                    } else {
                        uiMsg
                    }
                }.sortedBy { it.timestamp }
            }
            if (status == MessageMetadataService.MessageStatus.FAILED_NO_ACK || status == MessageMetadataService.MessageStatus.FAILED_TO_SEND){
                 _errorMessage.value = "Message ${messageId.toString().take(8)}... failed to send."
            }
        }?.launchIn(viewModelScope)
    }

    /**
     * Clears the currently displayed error message.
     */
    fun clearErrorMessage() {
        _errorMessage.value = null
    }

    override fun onCleared() {
        super.onCleared()
        messageMetadataService?.destroy()
        Log.d(TAG, "ChatViewModel onCleared.")
    }
}
