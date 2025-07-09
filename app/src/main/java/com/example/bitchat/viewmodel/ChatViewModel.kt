package com.example.bitchat.viewmodel

import android.app.Application
import android.bluetooth.BluetoothDevice
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.bitchat.MainActivity // Assuming for isAppInForeground check
import com.example.bitchat.data.MessageRepository
import com.example.bitchat.models.BitchatMessage
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.models.BinaryProtocol
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.services.EncryptionService
import com.example.bitchat.services.MessageMetadataService // Assuming this service exists
import com.example.bitchat.services.NotificationService // Assuming this service exists
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Locale
import java.util.UUID
// Remove javax.crypto.spec.SecretKeySpec if not directly used here for shared secrets
// import javax.crypto.spec.SecretKeySpec // Example, if creating shared secrets directly

/**
 * Represents a message object tailored for display in the UI.
 * Matches the existing UiMessage in the provided ChatViewModel code.
 */
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
        private const val DEFAULT_CHANNEL = "#general"
    }

    // --- Dependencies ---
    private val dataStorageService = DataStorageService(application)
    private val encryptionSvc = EncryptionService()
    private val messageRepository: MessageRepository = MessageRepository(dataStorageService)
    private val notificationService = NotificationService(application) // Instantiate if needed

    private var bluetoothMeshService: BluetoothMeshService? = null
    private var messageMetadataService: MessageMetadataService? = null // Will be set via setBluetoothServices

    // --- User Identity ---
    private var currentUserPublicKey: PublicKey? = null
    private var currentUserPrivateKey: PrivateKey? = null
    private var ephemeralPeerId: String = UUID.randomUUID().toString() // Default, will be loaded/generated

    // --- UI State ---
    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    val messages: StateFlow<List<UiMessage>> = _messages.asStateFlow()

    private val _currentChannel = MutableStateFlow(DEFAULT_CHANNEL)
    val currentChannel: StateFlow<String> = _currentChannel.asStateFlow()

    private val _inputText = MutableStateFlow("")
    val inputText: StateFlow<String> = _inputText.asStateFlow()

    private val _displayName = MutableStateFlow("User")
    val displayName: StateFlow<String> = _displayName.asStateFlow()

    private val _isBluetoothReady = MutableStateFlow(false) // Reflects scanning/advertising state
    val isBluetoothReady: StateFlow<Boolean> = _isBluetoothReady.asStateFlow()

    private val _connectedPeers = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val connectedPeers: StateFlow<List<BluetoothDevice>> = _connectedPeers.asStateFlow()

    private val _isSendingMessage = MutableStateFlow(false)
    val isSendingMessage: StateFlow<Boolean> = _isSendingMessage.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    init {
        Log.d(TAG, "ViewModel initialized.")
        viewModelScope.launch {
            dataStorageService.preloadPeerPublicKeysCache() // Preload known peer keys
            loadAndPrepareUserIdentity() // Load keys, then ID, then announce
        }
        observeCurrentChannelMessages()
        // observeBluetoothServiceStates and observeMessageStatusUpdates are called in setBluetoothServices
        // observeIncomingPackets is also called in setBluetoothServices (via processedReceivedPacketsFlow)
    }

    private suspend fun loadAndPrepareUserIdentity() {
        loadCurrentUserKeys() // Loads or generates Ed25519 keys
        generateAndLoadEphemeralId() // Loads or generates ephemeral ID
        // Announce self once both keys and ephemeral ID are confirmed
        if (currentUserPublicKey != null && currentUserPrivateKey != null && ephemeralPeerId.isNotEmpty()) {
            announceSelf()
        } else {
            Log.w(TAG, "User identity not fully ready after load; self-announce deferred.")
        }
    }

    private suspend fun loadCurrentUserKeys() {
        withContext(Dispatchers.IO) {
            val keyPair = dataStorageService.getOrGenerateIdentityKeyPair() // From Android Keystore
            if (keyPair != null) {
                currentUserPublicKey = keyPair.public
                currentUserPrivateKey = keyPair.private
                Log.i(TAG, "User Ed25519 identity keys loaded/generated successfully.")
            } else {
                Log.e(TAG, "CRITICAL: Failed to load or generate user identity keys.")
                _errorMessage.value = "Error: Could not initialize user identity. Messaging will fail."
            }
        }
    }

    private suspend fun generateAndLoadEphemeralId() {
        val storedId = dataStorageService.getUserEphemeralId()
        if (storedId != null) {
            ephemeralPeerId = storedId
            Log.d(TAG, "Loaded ephemeral peer ID: $ephemeralPeerId")
        } else {
            ephemeralPeerId = UUID.randomUUID().toString() // Generate new one
            dataStorageService.saveUserEphemeralId(ephemeralPeerId)
            Log.d(TAG, "Generated and saved new ephemeral peer ID: $ephemeralPeerId")
        }
        // Update displayName if it's the default "User" to include part of the new ID
        if (_displayName.value == "User") {
            val defaultName = "User-${ephemeralPeerId.substring(0, 4)}"
            _displayName.value = defaultName
            dataStorageService.saveDisplayName(defaultName) // Save the generated default name
        }
    }

    private fun loadDisplayName() { // Called from init before generateAndLoadEphemeralId potentially updates it
        viewModelScope.launch {
            dataStorageService.displayNameFlow.firstOrNull()?.let { name ->
                _displayName.value = name
            }
            // If still "User" after this, generateAndLoadEphemeralId will set a default like User-xxxx
             Log.d(TAG, "Initial display name loaded: ${_displayName.value}")
        }
    }


    private fun observeCurrentChannelMessages() {
        viewModelScope.launch {
            _currentChannel.flatMapLatest { channelName ->
                messageRepository.getMessagesForChannel(channelName)
            }.catch { e ->
                Log.e(TAG, "Error observing messages for ${currentChannel.value}: ${e.message}", e)
                _errorMessage.value = "Error loading messages for ${currentChannel.value}."
            }.collect { channelMessages ->
                Log.d(TAG, "Loaded ${channelMessages.size} messages for channel ${currentChannel.value}")
                _messages.value = channelMessages
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
            return
        }

        val currentPrivKey = currentUserPrivateKey
        if (currentPrivKey == null) {
            viewModelScope.launch { _errorMessage.value = "Cannot send message: User identity not ready (no private key)." }
            return
        }
        if (bluetoothMeshService == null) {
            viewModelScope.launch { _errorMessage.value = "Cannot send message: Bluetooth service not available." }
            return
        }

        _isSendingMessage.value = true
        val optimisticTimestamp = System.currentTimeMillis()
        val optimisticPacketId = UUID.randomUUID()

        val optimisticUiMessage = UiMessage(
            id = optimisticPacketId,
            senderName = _displayName.value,
            text = currentText,
            timestamp = optimisticTimestamp,
            isFromCurrentUser = true,
            channel = _currentChannel.value
        )
        // Optimistic UI update
        _messages.value = (_messages.value + optimisticUiMessage).sortedBy { it.timestamp }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bitchatMessage = BitchatMessage.UserMessage(
                    channel = _currentChannel.value,
                    senderDisplayName = _displayName.value,
                    text = currentText,
                    isPrivate = false, // TODO: Implement private messaging logic
                    isCompressed = false // TODO: Implement compression decision logic
                )

                val serializedMessagePayload = BinaryProtocol.serializeMessage(bitchatMessage, encryptionSvc, null)
                if (serializedMessagePayload == null) {
                    Log.e(TAG, "Failed to serialize UserMessage for packet ${optimisticPacketId}")
                    _errorMessage.value = "Error: Could not prepare message."
                    removeOptimisticMessage(optimisticPacketId)
                    _isSendingMessage.value = false
                    return@launch
                }

                val packet = BitchatPacket(
                    id = optimisticPacketId,
                    sourceId = ephemeralPeerId,
                    message = bitchatMessage, // Store the object for context
                    messagePayloadBytes = serializedMessagePayload, // Crucial for signing
                    timestamp = optimisticTimestamp, // Use optimistic timestamp for packet too
                    ttl = 5
                )

                val dataToSign = packet.dataToSign() // Uses packet.messagePayloadBytes
                val signature = encryptionSvc.signEd25519(dataToSign, currentPrivKey)
                if (signature == null) {
                    Log.e(TAG, "Failed to sign packet ${packet.id}.")
                    _errorMessage.value = "Error: Could not sign message."
                    removeOptimisticMessage(optimisticPacketId)
                    _isSendingMessage.value = false
                    return@launch
                }
                packet.signature = signature

                val finalPacketBytes = BinaryProtocol.serializePacket(packet, encryptionSvc, null) // Pass null for sharedSecret for public messages
                if (finalPacketBytes == null) {
                    Log.e(TAG, "Failed to serialize the final BitchatPacket ${packet.id}")
                    _errorMessage.value = "Error: Could not finalize message packet."
                    removeOptimisticMessage(optimisticPacketId)
                    _isSendingMessage.value = false
                    return@launch
                }

                Log.d(TAG, "Requesting BluetoothMeshService to send ${finalPacketBytes.size} bytes for packet ${packet.id}")
                messageMetadataService?.trackNewOutgoingMessage(packet, null)
                bluetoothMeshService?.sendDataToPeers(finalPacketBytes, packet)

                // Persist the message that was actually sent (with packet's timestamp)
                // The optimistic UI message already uses this ID and timestamp.
                // We just ensure it's saved to the repository.
                messageRepository.saveMessage(_currentChannel.value, optimisticUiMessage) // ID and timestamp match packet

                // isSendingMessage will be set to false by MessageMetadataService update or timeout
                // For now, let's assume it's quick for this example, or rely on MessageMetadataService
                // _isSendingMessage.value = false // Or handle this based on ack/timeout from MessageMetadataService

            } catch (e: Exception) {
                Log.e(TAG, "Exception during sendMessage for packet ${optimisticPacketId}: ${e.message}", e)
                _errorMessage.value = "Send Error: ${e.localizedMessage}"
                messageMetadataService?.onSendFailed(optimisticPacketId, true)
                removeOptimisticMessage(optimisticPacketId)
                _isSendingMessage.value = false
            }
        }
    }

    private fun removeOptimisticMessage(packetId: UUID) {
        _messages.update { list -> list.filterNot { it.id == packetId } }
    }


    private fun handleCommand(commandText: String) {
        val parts = commandText.drop(1).split(" ", limit = 2)
        val command = parts.firstOrNull()?.lowercase(Locale.getDefault())
        val args = if (parts.size > 1) parts[1] else null
        Log.d(TAG, "Handling command: /$command, Args: $args")
        // Implement command handling as in the provided original code
        // (join, nick, create, id, clear, etc.)
        // For brevity, not fully re-pasting here, but it should be similar.
        when (command) {
            "join" -> args?.let { joinChannel(it.trim()) }
            "nick" -> args?.let { newNick -> changeDisplayNameUserInitiated(newNick.trim()) } // Renamed for clarity
            "id" -> showMyId()
            "clear" -> clearCurrentChannelMessages()
            // "create" -> args?.let { createChannel(it.trim()) } // Example
            else -> {
                 addMessageToUi("System", "Unknown command: $command", false, _currentChannel.value)
            }
        }
    }

    private fun clearCurrentChannelMessages() {
        viewModelScope.launch {
            messageRepository.clearMessagesForChannel(_currentChannel.value)
            addMessageToUi("System", "Messages for ${_currentChannel.value} cleared.", false, _currentChannel.value)
        }
    }

    private fun showMyId() {
        val pubKeyHex = currentUserPublicKey?.encoded?.joinToString("") { "%02x".format(it) } ?: "N/A"
        addMessageToUi(
            senderName = "System",
            text = "Ephemeral ID: $ephemeralPeerId\nDisplay Name: ${displayName.value}\nPublic Key (Ed25519): ${pubKeyHex.take(16)}...",
            isFromCurrentUser = false,
            channel = _currentChannel.value
        )
    }

    private fun joinChannel(channelNameInput: String) {
        val targetChannel = if (channelNameInput.startsWith("#")) channelNameInput else "#$channelNameInput"
        if (_currentChannel.value == targetChannel) {
            Log.d(TAG, "Already in channel: $targetChannel")
            return
        }
        Log.i(TAG, "Joining channel: $targetChannel")
        _currentChannel.value = targetChannel // Triggers message loading via flatMapLatest
        addMessageToUi("System", "Switched to channel: $targetChannel", false, targetChannel)
        // TODO: Send actual ChannelJoinRequest packet
    }

    private fun changeDisplayNameUserInitiated(newName: String) { // Renamed from original example
        if (newName.isNotBlank() && newName.length <= 30) {
            viewModelScope.launch {
                dataStorageService.saveDisplayName(newName)
                _displayName.value = newName // Update local state immediately
                addMessageToUi("System", "Display name changed to: $newName", false, _currentChannel.value)
                announceSelf() // Announce the new display name
            }
        } else {
             addMessageToUi("System", "Invalid display name. Must be 1-30 characters.", false, _currentChannel.value)
        }
    }

    private suspend fun announceSelf() {
        val pubKey = currentUserPublicKey
        val privKey = currentUserPrivateKey
        val sourceId = ephemeralPeerId

        if (pubKey == null || privKey == null ) {
            Log.w(TAG, "Cannot announce self: keys not fully available.")
            return
        }
        Log.d(TAG, "Preparing to announce self. Name: ${_displayName.value}, ID: $sourceId")

        withContext(Dispatchers.IO) {
            try {
                val announceMessage = BitchatMessage.Announce(
                    peerId = sourceId,
                    displayName = _displayName.value,
                    publicKey = pubKey.encoded
                )
                val serializedAnnouncePayload = BinaryProtocol.serializeMessage(announceMessage, encryptionSvc)
                if (serializedAnnouncePayload == null) {
                    Log.e(TAG, "Failed to serialize Announce message for signing during self-announce.")
                    _errorMessage.value = "Error: Could not prepare self-announcement."
                    return@withContext
                }

                val packet = BitchatPacket(
                    sourceId = sourceId,
                    message = announceMessage, // Keep the object for context
                    messagePayloadBytes = serializedAnnouncePayload, // Crucial for dataToSign
                    ttl = 2
                )

                val dataToSign = packet.dataToSign() // Uses packet.messagePayloadBytes
                packet.signature = encryptionSvc.signEd25519(dataToSign, privKey)
                if (packet.signature == null) {
                    Log.e(TAG, "Failed to sign self-announce packet.")
                    _errorMessage.value = "Error: Could not sign self-announcement."
                    return@withContext
                }

                val finalPacketBytes = BinaryProtocol.serializePacket(packet, encryptionSvc)
                if (finalPacketBytes != null) {
                    bluetoothMeshService?.sendDataToPeers(finalPacketBytes, packet)
                    Log.i(TAG, "Sent self-announce message for $sourceId.")
                } else {
                    Log.e(TAG, "Failed to serialize self-announce packet.")
                    _errorMessage.value = "Error: Could not serialize self-announcement packet."
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error sending self-announce: ${e.message}", e)
                _errorMessage.value = "Announcement Error: ${e.message ?: "Unknown error"}"
            }
        }
    }


    fun onPacketReceived(packet: BitchatPacket) {
        Log.d(TAG, "Packet received in ViewModel: ID=${packet.id}, From=${packet.sourceId}, Type=${packet.message::class.simpleName}, PayloadSize=${packet.messagePayloadBytes?.size ?: "N/A"}")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                // 1. Store public key if it's an Announce message
                if (packet.message is BitchatMessage.Announce) {
                    val announceMsg = packet.message as BitchatMessage.Announce
                    if (announceMsg.publicKey.isNotEmpty()) {
                        Log.i(TAG, "Processing Announce from ${announceMsg.peerId} (${announceMsg.displayName}). Storing public key.")
                        dataStorageService.savePeerPublicKey(announceMsg.peerId, announceMsg.publicKey)
                    } else {
                        Log.w(TAG, "Received Announce from ${announceMsg.peerId} but its public key was empty.")
                    }
                }

                // 2. Verify signature
                if (packet.signature == null) {
                    Log.w(TAG, "Packet ${packet.id} from ${packet.sourceId} has no signature. Processing cautiously or dropping if not Announce.")
                    if (packet.message !is BitchatMessage.Announce) return@launch // Drop non-announce unsigned packets
                } else {
                    val senderPublicKeyBytes = dataStorageService.getPeerPublicKey(packet.sourceId)
                    if (senderPublicKeyBytes == null) {
                        Log.w(TAG, "No public key found for peer ${packet.sourceId} to verify packet ${packet.id}. Dropped (unless Announce, already processed key).")
                        if (packet.message !is BitchatMessage.Announce) return@launch
                        // If it's an Announce, we might have just stored its key. Verification might be against the key it carries.
                        // This part could be complex depending on trust model for first contact.
                        // For now, if it's Announce and we had no key, we assume it's a new peer and proceed.
                    } else {
                        val senderPublicKey = encryptionSvc.getEd25519PublicKeyFromBytes(senderPublicKeyBytes)
                        if (senderPublicKey == null) {
                            Log.e(TAG, "Could not reconstruct public key for peer ${packet.sourceId} from stored bytes. Packet ${packet.id} dropped.")
                            return@launch
                        }
                        // packet.messagePayloadBytes should have been populated by BinaryProtocol.deserializePacket
                        val dataForVerification = packet.dataToSign() // Uses packet.messagePayloadBytes
                        if (!encryptionSvc.verifyEd25519(dataForVerification, packet.signature!!, senderPublicKey)) {
                            Log.w(TAG, "Packet signature verification FAILED for ${packet.id} from ${packet.sourceId}. Type: ${packet.message::class.simpleName}")
                            return@launch
                        }
                        Log.i(TAG, "Packet signature VERIFIED for ${packet.id} from ${packet.sourceId}")
                    }
                }

                // 3. Process the message content
                val receivedMessage = packet.message
                when (receivedMessage) {
                    is BitchatMessage.UserMessage -> {
                        Log.i(TAG, "Processing UserMessage from ${receivedMessage.senderDisplayName} in #${receivedMessage.channel}: ${receivedMessage.text.take(30)}...")
                        val uiMsg = UiMessage(
                            id = packet.id,
                            senderName = receivedMessage.senderDisplayName,
                            text = receivedMessage.text,
                            timestamp = packet.timestamp,
                            isFromCurrentUser = (packet.sourceId == ephemeralPeerId),
                            channel = receivedMessage.channel
                        )
                        messageRepository.saveMessage(receivedMessage.channel, uiMsg)

                        val mainActivity = getApplication<Application>() as? MainActivity
                        val appInForeground = mainActivity?.isAppInForeground ?: true // Assume foreground if unknown

                        if (!uiMsg.isFromCurrentUser && (!appInForeground || _currentChannel.value != uiMsg.channel)) {
                            notificationService.showNewMessageNotification(
                                uiMsg.senderName,
                                uiMsg.text,
                                uiMsg.channel
                            )
                        }
                    }
                    is BitchatMessage.Announce -> {
                        // Key already stored. Log additional info or update peer list UI if any.
                        addMessageToUi("System", "Peer Announcement: ${receivedMessage.displayName} (${receivedMessage.peerId.take(8)}...) is on the network.", false, _currentChannel.value)
                    }
                    // ... other BitchatMessage types from original file ...
                    is BitchatMessage.Ack -> {
                        Log.i(TAG, "ACK received for our message: ${receivedMessage.messageId}")
                        messageMetadataService?.onAckReceived(receivedMessage.messageId)
                        _isSendingMessage.value = false // Assuming ACK means message fully sent for this example
                    }
                    else -> {
                        Log.d(TAG, "Received unhandled BitchatMessage type in onPacketReceived: ${receivedMessage::class.simpleName}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing received packet ${packet.id}: ${e.message}", e)
                _errorMessage.value = "Receive Error: ${e.message ?: "Unknown error"}"
            }
        }
    }

    private fun addMessageToUi(senderName: String, text: String, isFromCurrentUser: Boolean, channel: String) {
        val uiMsg = UiMessage(
            senderName = senderName,
            text = text,
            timestamp = System.currentTimeMillis(),
            isFromCurrentUser = isFromCurrentUser,
            channel = channel
        )
        // Add to the specific channel's list if different from current, or directly if current
        if (channel == _currentChannel.value) {
            _messages.update { currentList -> (currentList + uiMsg).sortedBy { it.timestamp } }
        } else {
            // If message is for a non-active channel, it's saved by onPacketReceived->messageRepository
            // This helper is more for system messages in the *current* channel.
            Log.d(TAG, "addMessageToUi called for non-current channel $channel, message: $text. Not adding to current UI.")
        }
    }

    fun setBluetoothServices(service: BluetoothMeshService) {
        this.bluetoothMeshService = service
        this.messageMetadataService = MessageMetadataService(service, viewModelScope) // Pass scope
        Log.d(TAG, "BluetoothMeshService and MessageMetadataService instances set in ViewModel.")
        observeBluetoothServiceStates(service)
        observeMessageStatusUpdates() // For sent messages
        observeIncomingRawPackets(service) // For received messages
    }

    private fun observeBluetoothServiceStates(service: BluetoothMeshService) {
        service.isScanning
            .onEach { scanning -> _isBluetoothReady.value = scanning || (bluetoothMeshService?.isAdvertising?.value ?: false) }
            .launchIn(viewModelScope)
        service.isAdvertising
            .onEach { advertising -> _isBluetoothReady.value = advertising || (bluetoothMeshService?.isScanning?.value ?: false) }
            .launchIn(viewModelScope)
        service.connectedDevices
            .onEach { peers -> _connectedPeers.value = peers }
            .launchIn(viewModelScope)
    }

    private fun observeIncomingRawPackets(service: BluetoothMeshService) {
         service.processedReceivedPacketsFlow // Assuming this flow exists in BluetoothMeshService
            .onEach { packet -> onPacketReceived(packet) } // packet is BitchatPacket
            .catch { e -> Log.e(TAG, "Error in processedReceivedPacketsFlow: ${e.message}", e) }
            .launchIn(viewModelScope)
        Log.d(TAG, "Started observing processed packets from Bluetooth service.")
    }


    private fun observeMessageStatusUpdates() {
        messageMetadataService?.messageStatusUpdates?.onEach { (messageId, status) ->
            Log.d(TAG, "Message $messageId status update: $status")
            if (status == MessageMetadataService.MessageStatus.SENT_AWAITING_ACK ||
                status == MessageMetadataService.MessageStatus.DELIVERED ||
                status == MessageMetadataService.MessageStatus.FAILED_NO_ACK ||
                status == MessageMetadataService.MessageStatus.FAILED_TO_SEND) {
                _isSendingMessage.value = false // Stop sending indicator once it's definitively sent or failed.
            }
            // Update UI based on message status (e.g., show delivery ticks or failure notice)
             _messages.update { currentMessages ->
                currentMessages.map { uiMsg ->
                    if (uiMsg.id == messageId) {
                        when (status) {
                            MessageMetadataService.MessageStatus.FAILED_NO_ACK,
                            MessageMetadataService.MessageStatus.FAILED_TO_SEND -> uiMsg.copy(text = "${uiMsg.text} (Failed)")
                            MessageMetadataService.MessageStatus.DELIVERED -> uiMsg.copy(text = "${uiMsg.text} (Delivered ✓)") // Example tick
                            else -> uiMsg
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

    fun clearErrorMessage() {
        _errorMessage.value = null
    }

    override fun onCleared() {
        super.onCleared()
        messageMetadataService?.destroy()
        Log.d(TAG, "ChatViewModel onCleared.")
    }
}
