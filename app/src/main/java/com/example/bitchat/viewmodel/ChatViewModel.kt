package com.example.bitchat.viewmodel

import android.app.Application
import android.bluetooth.BluetoothDevice
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.bitchat.MainActivity
import com.example.bitchat.data.ChannelRepository
import com.example.bitchat.data.MessageRepository
import com.example.bitchat.models.BinaryProtocol
import com.example.bitchat.models.BitchatMessage
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.models.ChannelInfo
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.services.EncryptionService
import com.example.bitchat.services.MessageMetadataService
import com.example.bitchat.services.NotificationService
import com.example.bitchat.services.PeerConnectivityInfo
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

/**
 * Data class for displaying peer information in the UI, e.g., for channel creation.
 */
data class PeerDisplayInfo(
    val peerId: String, // The persistent ID (e.g., hash of public key) or ephemeral ID
    val displayName: String,
    val isOnline: Boolean // Simplified online status
)

class ChatViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "ChatViewModel"
        private const val DEFAULT_CHANNEL = "#general"
    }

    private val dataStorageService = DataStorageService(application)
    private val encryptionSvc = EncryptionService()
    private val messageRepository: MessageRepository = MessageRepository(dataStorageService)
    private val channelRepository: ChannelRepository = ChannelRepository(dataStorageService)
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

    private val _bleOperationState = MutableStateFlow<BluetoothMeshService.BleOperationState>(BluetoothMeshService.BleOperationState.IDLE)
    val bleOperationState: StateFlow<BluetoothMeshService.BleOperationState> = _bleOperationState.asStateFlow()

    private val _connectedPeers = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val connectedPeers: StateFlow<List<BluetoothDevice>> = _connectedPeers.asStateFlow()

    private val _isSendingMessage = MutableStateFlow(false)
    val isSendingMessage: StateFlow<Boolean> = _isSendingMessage.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _allChannels = MutableStateFlow<List<ChannelInfo>>(emptyList())
    val allChannels: StateFlow<List<ChannelInfo>> = _allChannels.asStateFlow()

    // --- State for Peer Selection in UI ---
    private val _availablePeers = MutableStateFlow<List<PeerDisplayInfo>>(emptyList())
    /** Exposes a list of known peers for UI components like channel creation. */
    val availablePeers: StateFlow<List<PeerDisplayInfo>> = _availablePeers.asStateFlow()

    init {
        Log.i(TAG, "ViewModel initialized. Instance: ${this.hashCode()}")
        viewModelScope.launch {
            dataStorageService.preloadPeerPublicKeysCache()
            channelRepository.ensureDefaultChannelExists(DEFAULT_CHANNEL)
            loadAndPrepareUserIdentity()
        }
        observeCurrentChannelMessages()
        observeAllChannels()
        observeKnownPeers() // Start observing known peers for UI
        loadDisplayName()
    }

    private fun observeAllChannels() { /* ... (same as before) ... */ }
    private suspend fun loadAndPrepareUserIdentity() { /* ... (same as before) ... */ }
    private suspend fun loadCurrentUserKeys() { /* ... (same as before) ... */ }
    private suspend fun generateAndLoadEphemeralId() { /* ... (same as before) ... */ }
    private fun loadDisplayName() { /* ... (same as before) ... */ }
    private fun observeCurrentChannelMessages() { /* ... (same as before) ... */ }
    fun onInputTextChanged(newText: String) { /* ... (same as before) ... */ }
    fun sendMessage(text: String) { /* ... (same as before) ... */ }
    private fun removeOptimisticMessage(packetId: UUID) { /* ... (same as before) ... */ }
    private fun handleCommand(commandText: String) { /* ... (same as before, including requestCreateChannel) ... */ }

    private fun observeKnownPeers() {
        Log.d(TAG, "Setting up observer for known peers.")
        bluetoothMeshService?.knownPeersStateFlow
            ?.onEach { peersMap ->
                Log.d(TAG, "Known peers map updated. Size: ${peersMap.size}")
                val displayList = peersMap.values.map { peerInfo ->
                    // Attempt to get a display name from an Announce message if we have it, otherwise use address.
                    // This logic could be enhanced by storing display names in DataStorageService alongside public keys.
                    val displayName = peerInfo.bluetoothDevice?.name ?: peerInfo.deviceAddress
                    PeerDisplayInfo(
                        peerId = peerInfo.deviceAddress, // Using MAC address as the unique ID for selection
                        displayName = displayName,
                        isOnline = peerInfo.connectionState is BluetoothMeshService.BleOperationState.CONNECTED_AS_CLIENT ||
                                 peerInfo.connectionState is BluetoothMeshService.BleOperationState.CONNECTED_AS_SERVER
                    )
                }
                _availablePeers.value = displayList
                Log.i(TAG, "Available peers list for UI updated. Size: ${displayList.size}")
            }
            ?.catch { e -> Log.e(TAG, "Error in knownPeersStateFlow: ${e.message}", e) }
            ?.launchIn(viewModelScope)
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

            // TODO: Hash password
            val allMembers = (memberPeerIds + ephemeralPeerId).distinct() // Ensure self is a member

            val newChannel = ChannelInfo(
                name = effectiveChannelName,
                memberPeerIds = allMembers,
                isPrivate = isPrivate,
                lastActivityTimestamp = System.currentTimeMillis()
            )
            channelRepository.addOrUpdateChannel(newChannel)
            Log.i(TAG, "New channel '$effectiveChannelName' (ID: ${newChannel.id}) with members ${allMembers.joinToString()} added to repository.")

            // TODO: Send BitchatMessage.ChannelCreateRequest packet
            withContext(Dispatchers.Main) {
                addMessageToUi("System", "Channel '$effectiveChannelName' created locally.", false, _currentChannel.value)
                changeChannelByName(newChannel.name)
            }
        }
    }

    private fun clearCurrentChannelMessages() { /* ... (same as before) ... */ }
    private fun showMyId() { /* ... (same as before) ... */ }
    fun changeChannelByName(channelNameInput: String) { /* ... (same as before) ... */ }
    private fun changeDisplayNameUserInitiated(newName: String) { /* ... (same as before) ... */ }
    private suspend fun announceSelf() { /* ... (same as before) ... */ }
    fun onPacketReceived(packet: BitchatPacket) { /* ... (same as before) ... */ }
    private fun addMessageToUi(senderName: String, text: String, isFromCurrentUser: Boolean, channel: String) { /* ... (same as before) ... */ }

    fun setBluetoothServices(service: BluetoothMeshService) {
        Log.i(TAG, "BluetoothMeshService instance being set in ViewModel.")
        this.bluetoothMeshService = service
        this.messageMetadataService = MessageMetadataService(service, viewModelScope)
        observeBluetoothServiceStates(service)
        observeMessageStatusUpdates()
        observeIncomingRawPackets(service)
        observeKnownPeers() // Start observing peers now that service is available
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

        // This is a simplified peer list. A more robust solution might use the knownPeersStateFlow.
        service.connectedGattClientDevices
            .map { it.values.map { gatt -> gatt.device } }
            .onEach { peers -> _connectedPeers.value = peers }
            .catch {e -> Log.e(TAG, "Error in connectedGattClientDevices flow: ${e.message}", e)}
            .launchIn(viewModelScope)
    }

    private fun observeIncomingRawPackets(service: BluetoothMeshService) { /* ... (same as before) ... */ }
    private fun observeMessageStatusUpdates() { /* ... (same as before) ... */ }
    fun clearErrorMessage() { /* ... (same as before) ... */ }
    override fun onCleared() { /* ... (same as before) ... */ }
}
