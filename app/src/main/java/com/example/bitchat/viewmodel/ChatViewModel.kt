package com.example.bitchat.viewmodel

import android.app.Application
import android.bluetooth.BluetoothDevice
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.bitchat.MainActivity
import com.example.bitchat.data.MessageRepository
import com.example.bitchat.data.ChannelRepository // Import ChannelRepository
import com.example.bitchat.models.BitchatMessage
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.models.BinaryProtocol
import com.example.bitchat.models.ChannelInfo // Import ChannelInfo
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.services.EncryptionService
import com.example.bitchat.services.MessageMetadataService
import com.example.bitchat.services.NotificationService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Locale
import java.util.UUID

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

    private val dataStorageService = DataStorageService(application)
    private val encryptionSvc = EncryptionService()
    private val messageRepository: MessageRepository = MessageRepository(dataStorageService)
    private val channelRepository: ChannelRepository = ChannelRepository(dataStorageService) // Instantiate ChannelRepository
    private val notificationService = NotificationService(application)

    private var bluetoothMeshService: BluetoothMeshService? = null
    private var messageMetadataService: MessageMetadataService? = null

    private var currentUserPublicKey: PublicKey? = null
    private var currentUserPrivateKey: PrivateKey? = null
    private var ephemeralPeerId: String = UUID.randomUUID().toString()

    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    val messages: StateFlow<List<UiMessage>> = _messages.asStateFlow()

    private val _currentChannel = MutableStateFlow(DEFAULT_CHANNEL)
    val currentChannel: StateFlow<String> = _currentChannel.asStateFlow()

    private val _inputText = MutableStateFlow("")
    val inputText: StateFlow<String> = _inputText.asStateFlow()

    private val _displayName = MutableStateFlow("User")
    val displayName: StateFlow<String> = _displayName.asStateFlow()

    private val _bleOperationState = MutableStateFlow(BluetoothMeshService.BleOperationState.IDLE)
    val bleOperationState: StateFlow<BluetoothMeshService.BleOperationState> = _bleOperationState.asStateFlow()

    private val _connectedPeers = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val connectedPeers: StateFlow<List<BluetoothDevice>> = _connectedPeers.asStateFlow()

    private val _isSendingMessage = MutableStateFlow(false)
    val isSendingMessage: StateFlow<Boolean> = _isSendingMessage.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    // --- Channel Management State ---
    private val _allChannels = MutableStateFlow<List<ChannelInfo>>(emptyList())
    val allChannels: StateFlow<List<ChannelInfo>> = _allChannels.asStateFlow()

    init {
        Log.i(TAG, "ViewModel initialized. Instance: ${this.hashCode()}")
        viewModelScope.launch {
            dataStorageService.preloadPeerPublicKeysCache()
            channelRepository.ensureDefaultChannelExists(DEFAULT_CHANNEL) // Ensure default channel exists
            loadAndPrepareUserIdentity()
        }
        observeCurrentChannelMessages()
        observeAllChannels() // Observe the list of all channels
        loadDisplayName()
    }

    private fun observeAllChannels() {
        Log.d(TAG, "Setting up observer for all channels list.")
        channelRepository.allChannelsFlow
            .catch { e -> Log.e(TAG, "Error in allChannelsFlow: ${e.message}", e) }
            .onEach { channels ->
                Log.i(TAG, "All channels list updated in ViewModel. Count: ${channels.size}. Channels: ${channels.joinToString { it.name }}")
                _allChannels.value = channels // Already sorted by repo or can be sorted here if needed
            }
            .launchIn(viewModelScope)
    }

    private suspend fun loadAndPrepareUserIdentity() {
        Log.d(TAG, "Starting to load and prepare user identity.")
        loadCurrentUserKeys()
        generateAndLoadEphemeralId()
        if (currentUserPublicKey != null && currentUserPrivateKey != null && ephemeralPeerId.isNotEmpty()) {
            Log.i(TAG, "User identity fully prepared. Announcing self.")
            announceSelf()
        } else {
            Log.w(TAG, "User identity not fully ready after load; self-announce deferred. PubKey: ${currentUserPublicKey!=null}, PrivKey: ${currentUserPrivateKey!=null}, EphID: $ephemeralPeerId")
        }
    }

    private suspend fun loadCurrentUserKeys() {
        Log.d(TAG, "Loading current user Ed25519 keys...")
        withContext(Dispatchers.IO) {
            val keyPair = dataStorageService.getOrGenerateIdentityKeyPair()
            if (keyPair != null) {
                currentUserPublicKey = keyPair.public
                currentUserPrivateKey = keyPair.private
                Log.i(TAG, "User Ed25519 identity keys loaded/generated successfully.")
            } else {
                Log.e(TAG, "CRITICAL: Failed to load or generate user identity keys.")
                _errorMessage.value = "Fatal Error: Could not initialize user identity. Messaging will be impaired."
            }
        }
    }

    private suspend fun generateAndLoadEphemeralId() {
        Log.d(TAG, "Loading/Generating ephemeral peer ID...")
        val storedId = dataStorageService.getUserEphemeralId()
        if (storedId != null) {
            ephemeralPeerId = storedId
            Log.i(TAG, "Loaded ephemeral peer ID: $ephemeralPeerId")
        } else {
            ephemeralPeerId = UUID.randomUUID().toString()
            dataStorageService.saveUserEphemeralId(ephemeralPeerId)
            Log.i(TAG, "Generated and saved new ephemeral peer ID: $ephemeralPeerId")
        }
        if (_displayName.value == "User" || _displayName.value.startsWith("User-")) {
            val defaultName = "User-${ephemeralPeerId.substring(0, 4)}"
            _displayName.value = defaultName
            dataStorageService.saveDisplayName(defaultName)
            Log.i(TAG, "Set default display name to $defaultName")
        }
    }

    private fun loadDisplayName() {
        viewModelScope.launch {
            val name = dataStorageService.displayNameFlow.firstOrNull()
            if (name != null && name != "User" && !name.startsWith("User-")) {
                 _displayName.value = name
                 Log.i(TAG, "Loaded display name: $name")
            } else {
                Log.d(TAG, "No custom display name found, will use/generate default if needed after ephemeral ID.")
            }
        }
    }

    private fun observeCurrentChannelMessages() {
        Log.d(TAG, "Setting up observer for current channel messages.")
        viewModelScope.launch {
            _currentChannel.flatMapLatest { channelName ->
                Log.d(TAG, "Current channel changed to $channelName, re-observing messages.")
                messageRepository.getMessagesForChannel(channelName)
            }.catch { e ->
                Log.e(TAG, "Error observing messages for ${currentChannel.value}: ${e.message}", e)
                _errorMessage.value = "Error loading messages for ${currentChannel.value}."
            }.collect { channelMessages ->
                Log.d(TAG, "Received ${channelMessages.size} messages for channel ${currentChannel.value}")
                _messages.value = channelMessages
            }
        }
    }

    fun onInputTextChanged(newText: String) {
        _inputText.value = newText
    }

    fun sendMessage(text: String) {
        val currentText = text.trim()
        Log.d(TAG, "sendMessage called with text: \"$currentText\"")
        if (currentText.isBlank()) {
            Log.w(TAG, "Attempted to send blank message.")
            return
        }
        if (_isSendingMessage.value) {
            Log.w(TAG, "Already sending a message, new message \"$currentText\" attempt ignored.")
            return
        }
        _inputText.value = ""

        if (currentText.startsWith("/")) {
            handleCommand(currentText)
            return
        }

        val currentPrivKey = currentUserPrivateKey
        if (currentPrivKey == null) {
            Log.e(TAG, "Cannot send message: User private key is not available.")
            viewModelScope.launch { _errorMessage.value = "Cannot send: Identity not ready." }
            return
        }
        if (bluetoothMeshService == null) {
            Log.e(TAG, "Cannot send message: Bluetooth service not available.")
            viewModelScope.launch { _errorMessage.value = "Cannot send: Bluetooth not ready." }
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
        _messages.value = (_messages.value + optimisticUiMessage).sortedBy { it.timestamp }
        Log.d(TAG, "Optimistic UI update for message ${optimisticUiMessage.id}.")

        viewModelScope.launch(Dispatchers.IO) {
            Log.d(TAG, "Preparing to send message ID ${optimisticPacketId} in background.")
            try {
                val bitchatMessage = BitchatMessage.UserMessage(
                    channel = _currentChannel.value,
                    senderDisplayName = _displayName.value,
                    text = currentText,
                    isPrivate = false,
                    isCompressed = true
                )

                val serializedMessagePayload = BinaryProtocol.serializeMessage(bitchatMessage, encryptionSvc, null)
                if (serializedMessagePayload == null) {
                    Log.e(TAG, "Failed to serialize UserMessage for packet ${optimisticPacketId}")
                    _errorMessage.value = "Error: Could not prepare message."
                    removeOptimisticMessage(optimisticPacketId)
                    _isSendingMessage.value = false
                    return@launch
                }
                Log.d(TAG, "UserMessage ${optimisticPacketId} serialized to ${serializedMessagePayload.size} bytes.")

                val packet = BitchatPacket(
                    id = optimisticPacketId,
                    sourceId = ephemeralPeerId,
                    message = bitchatMessage,
                    messagePayloadBytes = serializedMessagePayload,
                    timestamp = optimisticTimestamp,
                    ttl = 5
                )

                val dataToSign = packet.dataToSign()
                val signature = encryptionSvc.signEd25519(dataToSign, currentPrivKey)
                if (signature == null) {
                    Log.e(TAG, "Failed to sign packet ${packet.id}.")
                    _errorMessage.value = "Error: Could not sign message."
                    removeOptimisticMessage(optimisticPacketId)
                    _isSendingMessage.value = false
                    return@launch
                }
                packet.signature = signature
                Log.d(TAG, "Packet ${packet.id} signed with signature length ${signature.size}.")

                val finalPacketBytes = BinaryProtocol.serializePacket(packet, encryptionSvc, null)
                if (finalPacketBytes == null) {
                    Log.e(TAG, "Failed to serialize the final BitchatPacket ${packet.id}")
                    _errorMessage.value = "Error: Could not finalize message packet."
                    removeOptimisticMessage(optimisticPacketId)
                    _isSendingMessage.value = false
                    return@launch
                }
                Log.d(TAG, "Final packet ${packet.id} serialized to ${finalPacketBytes.size} bytes.")

                messageMetadataService?.trackNewOutgoingMessage(packet, null)
                bluetoothMeshService?.sendDataToPeers(finalPacketBytes, packet)

                messageRepository.saveMessage(_currentChannel.value, optimisticUiMessage)
                channelRepository.updateChannelLastActivity(_currentChannel.value, optimisticTimestamp) // Update channel activity
                Log.i(TAG, "Message ID ${packet.id} sent to service and persisted. Text: \"${currentText.take(30)}...\"")

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
        Log.d(TAG, "Rolling back optimistic UI for message $packetId")
        _messages.update { list -> list.filterNot { it.id == packetId } }
    }

    private fun handleCommand(commandText: String) {
        val parts = commandText.drop(1).split(" ", limit = 2)
        val command = parts.firstOrNull()?.lowercase(Locale.getDefault())
        val args = if (parts.size > 1) parts[1] else null
        Log.i(TAG, "Handling command: /$command, Args: $args")

        when (command) {
            "join" -> args?.let { changeChannelByName(it.trim()) }
            "nick" -> args?.let { newNick -> changeDisplayNameUserInitiated(newNick.trim()) }
            "id" -> showMyId()
            "clear" -> clearCurrentChannelMessages()
            "announce" -> viewModelScope.launch { announceSelf() }
            "createchannel" -> args?.let { requestCreateChannel(it.trim(), emptyList(), false, null) }
            "sync" -> args?.let { requestPeerStateSync(it.trim()) } // Example: /sync <peer_address_or_id>
            else -> {
                 addMessageToUi("System", "Unknown command: /$command", false, _currentChannel.value)
            }
        }
    }

    fun requestCreateChannel(channelNameInput: String, memberPeerIds: List<String>, isPrivate: Boolean, passwordAttempt: String?) {
        val effectiveChannelName = if (channelNameInput.startsWith("#")) channelNameInput else "#$channelNameInput"
        Log.i(TAG, "User requested to create channel: Name='$effectiveChannelName', Members=${memberPeerIds.joinToString()}, Private=$isPrivate, PasswordSet=${passwordAttempt!=null}")

        viewModelScope.launch(Dispatchers.IO) {
            val existingChannel = channelRepository.getChannelByName(effectiveChannelName)
            if (existingChannel != null) {
                Log.w(TAG, "Channel '$effectiveChannelName' already exists. ID: ${existingChannel.id}")
                _errorMessage.value = "Channel '$effectiveChannelName' already exists."
                return@launch
            }

            // TODO: Hash password if private and passwordAttempt is not null
            // val passwordHash = if (isPrivate && passwordAttempt != null) encryptionSvc.deriveKeyFromPassword(passwordAttempt.toCharArray(), encryptionSvc.generateSalt())?.encoded else null
            // For now, ignoring password part for placeholder

            val newChannel = ChannelInfo(
                name = effectiveChannelName,
                memberPeerIds = memberPeerIds, // In future, this would be from peer selection UI
                isPrivate = isPrivate,
                lastActivityTimestamp = System.currentTimeMillis() // New channel, current activity
            )
            channelRepository.addOrUpdateChannel(newChannel)
            Log.i(TAG, "New channel '$effectiveChannelName' (ID: ${newChannel.id}) added to repository.")

            // TODO: Send BitchatMessage.ChannelCreateRequest packet to the network
            // For now, just locally add and switch
            withContext(Dispatchers.Main) {
                addMessageToUi("System", "Channel '$effectiveChannelName' created locally.", false, _currentChannel.value)
                changeChannelByName(newChannel.name) // Switch to the newly created channel
            }
        }
    }

    private fun clearCurrentChannelMessages() {
        viewModelScope.launch {
            Log.i(TAG, "Clearing messages for current channel: ${_currentChannel.value}")
            messageRepository.clearMessagesForChannel(_currentChannel.value)
            addMessageToUi("System", "Messages for ${_currentChannel.value} cleared.", false, _currentChannel.value)
        }
    }

    private fun showMyId() {
        val pubKeyHex = currentUserPublicKey?.encoded?.joinToString("") { "%02x".format(it) } ?: "Not available"
        val messageText = "Ephemeral ID: $ephemeralPeerId\nDisplay Name: ${displayName.value}\nPublic Key (Ed25519): ${pubKeyHex.take(16)}..."
        Log.d(TAG, "Showing My ID: $messageText")
        addMessageToUi("System", messageText, false, _currentChannel.value)
    }

    fun changeChannelByName(channelNameInput: String) { // Renamed from joinChannel
        val targetChannel = if (channelNameInput.startsWith("#")) channelNameInput else "#$channelNameInput"
        if (_currentChannel.value == targetChannel) {
            Log.d(TAG, "Already in channel: $targetChannel. No action taken.")
            return
        }
        Log.i(TAG, "User switching channel to: $targetChannel (from ${_currentChannel.value})")
        _currentChannel.value = targetChannel
        // Messages will update automatically due to flatMapLatest in observeCurrentChannelMessages
        addMessageToUi("System", "Switched to channel: $targetChannel", false, targetChannel)
        // TODO: If joining a new channel not previously known, might need to send ChannelJoinRequest
    }

    private fun changeDisplayNameUserInitiated(newName: String) {
        if (newName.isBlank() || newName.length > 30) {
            Log.w(TAG, "Invalid new display name attempt: '$newName'")
            addMessageToUi("System", "Invalid display name. Must be 1-30 characters.", false, _currentChannel.value)
            return
        }
        viewModelScope.launch {
            Log.i(TAG, "User changing display name to: '$newName'")
            dataStorageService.saveDisplayName(newName)
            _displayName.value = newName
            addMessageToUi("System", "Display name changed to: $newName", false, _currentChannel.value)
            announceSelf()
        }
    }

    private suspend fun announceSelf() {
        val pubKey = currentUserPublicKey
        val privKey = currentUserPrivateKey
        val sourceId = ephemeralPeerId

        if (pubKey == null || privKey == null ) {
            Log.e(TAG, "Cannot announce self: User keys not available (pubKey: ${pubKey!=null}, privKey: ${privKey!=null}).")
            _errorMessage.value = "Cannot announce: Identity not ready."
            return
        }
        Log.i(TAG, "Preparing to announce self. Name: '${_displayName.value}', ID: $sourceId, PubKey: ${pubKey.encoded.size}B")

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
                Log.d(TAG, "Announce message serialized to ${serializedAnnouncePayload.size} bytes for self-announce.")

                val packet = BitchatPacket(
                    sourceId = sourceId,
                    message = announceMessage,
                    messagePayloadBytes = serializedAnnouncePayload,
                    ttl = 2
                )

                val dataToSign = packet.dataToSign()
                packet.signature = encryptionSvc.signEd25519(dataToSign, privKey)
                if (packet.signature == null) {
                    Log.e(TAG, "Failed to sign self-announce packet ID ${packet.id}.")
                    _errorMessage.value = "Error: Could not sign self-announcement."
                    return@withContext
                }
                Log.d(TAG, "Self-announce packet ${packet.id} signed.")

                val finalPacketBytes = BinaryProtocol.serializePacket(packet, encryptionSvc)
                if (finalPacketBytes != null) {
                    bluetoothMeshService?.sendDataToPeers(finalPacketBytes, packet)
                    Log.i(TAG, "Sent self-announce message for $sourceId (Packet ID: ${packet.id}, Size: ${finalPacketBytes.size}B).")
                } else {
                    Log.e(TAG, "Failed to serialize self-announce packet ${packet.id}.")
                    _errorMessage.value = "Error: Could not serialize self-announcement packet."
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error sending self-announce: ${e.message}", e)
                _errorMessage.value = "Announcement Error: ${e.message ?: "Unknown error"}"
            }
        }
    }

    fun onPacketReceived(packet: BitchatPacket) {
        Log.i(TAG, "Packet received in ViewModel: ID=${packet.id}, From=${packet.sourceId}, Type=${packet.message::class.simpleName}, PayloadSize=${packet.messagePayloadBytes?.size ?: "N/A"}")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (packet.sourceId == ephemeralPeerId) {
                    Log.d(TAG, "Ignoring packet ${packet.id} from self.")
                    return@launch
                }

                if (packet.message is BitchatMessage.Announce) {
                    val announceMsg = packet.message as BitchatMessage.Announce
                    if (announceMsg.publicKey.isNotEmpty()) {
                        Log.i(TAG, "Processing Announce from ${announceMsg.peerId} ('${announceMsg.displayName}'). Storing public key (${announceMsg.publicKey.size}B).")
                        dataStorageService.savePeerPublicKey(announceMsg.peerId, announceMsg.publicKey)
                    } else {
                        Log.w(TAG, "Received Announce from ${announceMsg.peerId} but its public key was empty.")
                    }
                }

                if (packet.signature == null) {
                    Log.w(TAG, "Packet ${packet.id} from ${packet.sourceId} (Type: ${packet.message::class.simpleName}) has no signature. Processing depending on type.")
                    if (packet.message !is BitchatMessage.Announce) {
                        Log.w(TAG, "Packet ${packet.id} is not Announce and has no signature. Dropping.")
                        return@launch
                    }
                } else {
                    val senderPublicKeyBytes = dataStorageService.getPeerPublicKey(packet.sourceId)
                    if (senderPublicKeyBytes == null) {
                        Log.w(TAG, "No public key found for peer ${packet.sourceId} to verify packet ${packet.id} (Type: ${packet.message::class.simpleName}).")
                        if (packet.message !is BitchatMessage.Announce) {
                             Log.w(TAG, "Dropping non-Announce packet ${packet.id} due to missing sender public key for verification.")
                            return@launch
                        }
                        Log.i(TAG, "Allowing Announce packet ${packet.id} from new peer ${packet.sourceId} for key discovery, even if prior key unknown for sig check.")
                    } else {
                        val senderPublicKey = encryptionSvc.getEd25519PublicKeyFromBytes(senderPublicKeyBytes)
                        if (senderPublicKey == null) {
                            Log.e(TAG, "Could not reconstruct public key for peer ${packet.sourceId} from stored bytes. Packet ${packet.id} (Type: ${packet.message::class.simpleName}) dropped.")
                            return@launch
                        }
                        val dataForVerification = packet.dataToSign()
                        if (!encryptionSvc.verifyEd25519(dataForVerification, packet.signature!!, senderPublicKey)) {
                            Log.w(TAG, "Packet signature verification FAILED for ${packet.id} from ${packet.sourceId}. Type: ${packet.message::class.simpleName}")
                            return@launch
                        }
                        Log.i(TAG, "Packet signature VERIFIED for ${packet.id} from ${packet.sourceId} (Type: ${packet.message::class.simpleName})")
                    }
                }

                val receivedMessage = packet.message
                when (receivedMessage) {
                    is BitchatMessage.UserMessage -> {
                        Log.i(TAG, "Processing UserMessage from '${receivedMessage.senderDisplayName}' in #${receivedMessage.channel}: \"${receivedMessage.text.take(30)}...\"")
                        val uiMsg = UiMessage(
                            id = packet.id,
                            senderName = receivedMessage.senderDisplayName,
                            text = receivedMessage.text,
                            timestamp = packet.timestamp,
                            isFromCurrentUser = false,
                            channel = receivedMessage.channel
                        )
                        messageRepository.saveMessage(receivedMessage.channel, uiMsg)
                        channelRepository.updateChannelLastActivity(receivedMessage.channel, packet.timestamp) // Update channel activity
                        Log.d(TAG, "UserMessage ${packet.id} saved for channel ${receivedMessage.channel} & activity updated.")

                        val mainActivity = getApplication<Application>() as? MainActivity
                        val appInForeground = mainActivity?.isAppInForeground ?: true

                        if (!appInForeground || _currentChannel.value != uiMsg.channel) {
                            Log.d(TAG, "Showing notification for message ${packet.id} in channel ${uiMsg.channel} (App BG: ${!appInForeground}, Diff Chan: ${_currentChannel.value != uiMsg.channel})")
                            notificationService.showNewMessageNotification(uiMsg.senderName, uiMsg.text, uiMsg.channel)
                        }
                    }
                    is BitchatMessage.Announce -> {
                        addMessageToUi("System", "Peer Online: ${receivedMessage.displayName} (${receivedMessage.peerId.take(8)}...)", false, _currentChannel.value)
                    }
                    is BitchatMessage.Ack -> {
                        Log.i(TAG, "ACK received for our message ID: ${receivedMessage.messageId}")
                        messageMetadataService?.onAckReceived(receivedMessage.messageId)
                    }
                    else -> {
                        Log.d(TAG, "Received unhandled BitchatMessage type: ${receivedMessage::class.simpleName} from ${packet.sourceId}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing received packet ${packet.id} from ${packet.sourceId}: ${e.message}", e)
                _errorMessage.value = "Receive Error: ${e.message ?: "Unknown error"}"
            }
        }
    }

    private fun addMessageToUi(senderName: String, text: String, isFromCurrentUser: Boolean, channel: String) {
        val uiMsg = UiMessage(
            senderName = senderName, text = text,
            timestamp = System.currentTimeMillis(),
            isFromCurrentUser = isFromCurrentUser, channel = channel
        )
        if (channel == _currentChannel.value) {
            _messages.update { currentList -> (currentList + uiMsg).sortedBy { it.timestamp } }
        } else {
            Log.d(TAG, "System message for non-active channel '$channel': \"$text\". Not adding to current UI of '${_currentChannel.value}'.")
        }
    }

    fun setBluetoothServices(service: BluetoothMeshService) {
        Log.i(TAG, "BluetoothMeshService instance being set in ViewModel.")
        this.bluetoothMeshService = service
        this.messageMetadataService = MessageMetadataService(service, viewModelScope)
        observeBluetoothServiceStates(service)
        observeMessageStatusUpdates()
        observeIncomingRawPackets(service)
        viewModelScope.launch {
            delay(500)
            service.initializeBleOperations()
        }
    }

    private fun observeBluetoothServiceStates(service: BluetoothMeshService) {
        Log.d(TAG, "Observing Bluetooth service states.")
        service.bleOperationState
            .onEach { state ->
                _bleOperationState.value = state
                Log.i(TAG, "BLE Operation State in ViewModel updated to: $state")
            }
            .catch {e -> Log.e(TAG, "Error in bleOperationState flow: ${e.message}", e)}
            .launchIn(viewModelScope)

        service.connectedGattClientDevices
            .map { it.values.map { gatt -> gatt.device } }
            .onEach { peers -> _connectedPeers.value = peers }
            .catch {e -> Log.e(TAG, "Error in connectedGattClientDevices flow: ${e.message}", e)}
            .launchIn(viewModelScope)
    }

    private fun observeIncomingRawPackets(service: BluetoothMeshService) {
         service.processedReceivedPacketsFlow
            .onEach { packet -> onPacketReceived(packet) }
            .catch { e -> Log.e(TAG, "Error in processedReceivedPacketsFlow: ${e.message}", e) }
            .launchIn(viewModelScope)
        Log.d(TAG, "Observation of processed packets from Bluetooth service started.")
    }

    private fun observeMessageStatusUpdates() {
        messageMetadataService?.messageStatusUpdates?.onEach { (messageId, status) ->
            Log.d(TAG, "Message $messageId UI status update: $status")
            if (status == MessageMetadataService.MessageStatus.SENT_AWAITING_ACK ||
                status == MessageMetadataService.MessageStatus.DELIVERED ||
                status == MessageMetadataService.MessageStatus.FAILED_NO_ACK ||
                status == MessageMetadataService.MessageStatus.FAILED_TO_SEND) {
                if (_isSendingMessage.value) _isSendingMessage.value = false
            }
             _messages.update { currentMessages ->
                currentMessages.map { uiMsg ->
                    if (uiMsg.id == messageId) {
                        when (status) {
                            MessageMetadataService.MessageStatus.FAILED_NO_ACK,
                            MessageMetadataService.MessageStatus.FAILED_TO_SEND -> uiMsg.copy(text = "${uiMsg.text} (Failed)")
                            MessageMetadataService.MessageStatus.DELIVERED -> uiMsg.copy(text = "${uiMsg.text} (Delivered ✓)")
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
        }
        ?.catch {e -> Log.e(TAG, "Error in messageStatusUpdates flow: ${e.message}", e)}
        ?.launchIn(viewModelScope)
    }

    fun clearErrorMessage() {
        _errorMessage.value = null
    }

    override fun onCleared() {
        super.onCleared()
        messageMetadataService?.destroy()
        Log.i(TAG, "ChatViewModel onCleared. Instance: ${this.hashCode()}")
    }
}
