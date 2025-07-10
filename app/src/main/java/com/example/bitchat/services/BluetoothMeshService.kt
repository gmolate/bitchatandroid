package com.example.bitchat.services

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import com.example.bitchat.MainActivity
import com.example.bitchat.R
import com.example.bitchat.models.BitchatPacket
import com.example.bitchat.models.BinaryProtocol
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.pow

// --- Peer Connectivity Information ---
data class PeerConnectivityInfo(
    val deviceAddress: String,
    var bluetoothDevice: BluetoothDevice?, // Can be null if only address is known initially
    var connectionState: BleOperationState,
    var lastSeenTimestamp: Long = System.currentTimeMillis(),
    var reconnectionAttempts: Int = 0,
    var gatt: BluetoothGatt? = null, // Store the GATT object for client connections
    var isKnownGoodPeer: Boolean = false, // True if successfully connected at least once
    var wantsNotifications: Boolean = false // For GATT server: if this client subscribed to our characteristic
)

// --- Detailed BLE Operation State ---
sealed class BleOperationState {
    object IDLE : BleOperationState()
    object SCANNING : BleOperationState()
    object ADVERTISING : BleOperationState()
    data class CONNECTING_TO_PEER(val peerAddress: String) : BleOperationState()
    data class RECONNECTING_TO_PEER(val peerAddress: String, val attempt: Int) : BleOperationState()
    data class CONNECTED_AS_CLIENT(val peerAddress: String, val deviceName: String?) : BleOperationState()
    data class CONNECTED_AS_SERVER(val peerAddress: String, val deviceName: String?) : BleOperationState()
    object ERROR_PERMISSIONS : BleOperationState()
    object ERROR_BLUETOOTH_OFF : BleOperationState()
    data class ERROR_CONNECTION_FAILED(val peerAddress: String?, val errorCode: Int?, val isTimeout: Boolean = false) : BleOperationState()
    object ERROR_GENERIC : BleOperationState()

    override fun toString(): String {
        return when (this) {
            IDLE -> "Idle"
            SCANNING -> "Scanning for peers"
            ADVERTISING -> "Advertising self"
            is CONNECTING_TO_PEER -> "Connecting to ${peerAddress.takeLast(6)}"
            is RECONNECTING_TO_PEER -> "Reconnecting to ${peerAddress.takeLast(6)} (Attempt ${attempt})"
            is CONNECTED_AS_CLIENT -> "Connected to ${deviceName ?: peerAddress.takeLast(6)}"
            is CONNECTED_AS_SERVER -> "Peer connected: ${deviceName ?: peerAddress.takeLast(6)}"
            ERROR_PERMISSIONS -> "Error: Permissions needed"
            ERROR_BLUETOOTH_OFF -> "Error: Bluetooth is off"
            is ERROR_CONNECTION_FAILED -> "Error: Connection to ${peerAddress?.takeLast(6) ?: "Unknown"} ${if(isTimeout) "timed out" else "failed (code $errorCode)"}"
            ERROR_GENERIC -> "Error: BLE operation failed"
        }
    }
}


class BluetoothMeshService : Service() {

    private val binder = LocalBinder()
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private lateinit var bluetoothManager: BluetoothManager
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothLeScanner: BluetoothLeScanner? = null
    private var bluetoothLeAdvertiser: BluetoothLeAdvertiser? = null
    private var gattServer: BluetoothGattServer? = null

    // --- State Flows ---
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _isAdvertising = MutableStateFlow(false)
    val isAdvertising: StateFlow<Boolean> = _isAdvertising.asStateFlow()

    private val _bleOperationState = MutableStateFlow<BleOperationState>(BleOperationState.IDLE)
    val bleOperationState: StateFlow<BleOperationState> = _bleOperationState.asStateFlow()

    private val _processedReceivedPacketsFlow = MutableSharedFlow<BitchatPacket>(
        replay = 0, extraBufferCapacity = 128, onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val processedReceivedPacketsFlow: SharedFlow<BitchatPacket> = _processedReceivedPacketsFlow.asSharedFlow()

    // --- Peer Management ---
    // knownPeers stores information about devices we've interacted with or discovered.
    // The key is the device's MAC address.
    private val knownPeers = ConcurrentHashMap<String, PeerConnectivityInfo>()

    // gattClientConnections stores active BluetoothGatt objects for devices WE connected TO.
    // Key: device MAC address.
    private val gattClientConnections = ConcurrentHashMap<String, BluetoothGatt>()

    // gattServerConnections stores BluetoothDevice objects for devices connected TO US.
    // Key: device MAC address.
    private val gattServerConnections = ConcurrentHashMap<String, BluetoothDevice>()

    // subscribedDevices stores devices that have subscribed to notifications on our GATT server.
    // This is a Set of BluetoothDevice objects.
    private val subscribedDevices = Collections.synchronizedSet(HashSet<BluetoothDevice>())


    companion object {
        private const val TAG = "BTMeshService"
        private const val NOTIFICATION_CHANNEL_ID = "BitChatServiceChannel"
        private const val NOTIFICATION_ID = 101
        const val CONNECTION_TIMEOUT_MS = 30_000L // 30 seconds
        const val INITIAL_RECONNECTION_DELAY_MS = 5_000L // 5 seconds
        const val MAX_RECONNECTION_ATTEMPTS = 5
        const val MAX_RECONNECTION_DELAY_MS = 60_000L // 1 minute


        val BITCHAT_SERVICE_UUID: UUID = UUID.fromString("0000b17c-0000-1000-8000-00805f9b34fb")
        val BITCHAT_CHARACTERISTIC_UUID: UUID = UUID.fromString("0000b17d-0000-1000-8000-00805f9b34fb")
        val CLIENT_CHARACTERISTIC_CONFIG_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    inner class LocalBinder : Binder() {
        fun getService(): BluetoothMeshService = this@BluetoothMeshService
    }

    override fun onBind(intent: Intent): IBinder = binder.also { Log.d(TAG, "Service onBind") }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Service onCreate. Instance: ${this.hashCode()}")
        bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth not supported. Service stopping.")
            _bleOperationState.value = BleOperationState.ERROR_GENERIC
            stopSelf()
            return
        }
        if (!bluetoothAdapter!!.isEnabled) {
            Log.w(TAG, "Bluetooth is OFF. Operations will fail until enabled.")
            _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF
        }

        bluetoothLeScanner = bluetoothAdapter?.bluetoothLeScanner
        bluetoothLeAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        createNotificationChannel()
        Log.i(TAG, "Service created successfully.")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "Service onStartCommand. Action: ${intent?.action}, Flags: $flags, StartId: $startId")
        startForeground(NOTIFICATION_ID, createNotification())
        if (checkBlePermissions()) {
            if (bluetoothAdapter?.isEnabled == true) {
                Log.i(TAG, "Permissions OK and Bluetooth ON. Initializing BLE operations.")
                initializeBleOperations()
            } else {
                Log.w(TAG, "Permissions OK, but Bluetooth is OFF. Waiting for BT to be enabled.")
                _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF
            }
        } else {
            Log.w(TAG, "BLE permissions NOT granted. Cannot start BLE operations.")
            _bleOperationState.value = BleOperationState.ERROR_PERMISSIONS
        }
        return START_STICKY
    }

    fun initializeBleOperations() {
        if (bluetoothAdapter?.isEnabled != true) {
            Log.w(TAG, "Cannot initialize BLE: Bluetooth is off.")
            _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF
            return
        }
        if (!checkBlePermissions()) {
            Log.w(TAG, "Cannot initialize BLE: Permissions missing.")
            _bleOperationState.value = BleOperationState.ERROR_PERMISSIONS
            return
        }
        Log.i(TAG, "Initializing BLE operations: GATT Server, Advertising, Scanning.")
        _bleOperationState.value = BleOperationState.IDLE
        serviceScope.launch {
            startGattServer()
            startAdvertising()
            startScanning()
        }
    }

    private fun checkBlePermissions(): Boolean {
        // ... (permission checking logic remains the same as before, ensuring it's thorough)
        val requiredPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
        } else {
            listOf(Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN, Manifest.permission.ACCESS_FINE_LOCATION)
        }
        val allRequired = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S && !requiredPermissions.contains(Manifest.permission.ACCESS_FINE_LOCATION)) {
            requiredPermissions + Manifest.permission.ACCESS_FINE_LOCATION
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !requiredPermissions.contains(Manifest.permission.ACCESS_FINE_LOCATION)) {
             // For S+, ACCESS_FINE_LOCATION is not strictly needed if BLUETOOTH_SCAN has `neverForLocation`
             // but some OEMs might still behave better with it. Adding it for robustness.
            requiredPermissions + Manifest.permission.ACCESS_FINE_LOCATION
        }
        else {
            requiredPermissions
        }
        val missingPermissions = allRequired.filter { ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        return if (missingPermissions.isEmpty()) true.also { Log.v(TAG, "All BLE permissions granted.") }
               else false.also { Log.w(TAG, "Missing BLE permissions: $missingPermissions") }
    }

    private fun createNotificationChannel() { /* ... (same as before) ... */ }
    private fun createNotification(): Notification { /* ... (same as before, ensure R.drawable.ic_bitchat_notification exists) ... */
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntentFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val pendingIntent = PendingIntent.getActivity( this, 0, notificationIntent, pendingIntentFlags)
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("BitChat Mesh")
            .setContentText("Service is active.")
            .setSmallIcon(R.drawable.ic_bitchat_notification) // Ensure this exists
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    // --- Advertising ---
    @Synchronized
    fun startAdvertising() {
        // ... (Permission and adapter checks, then...)
        if (!checkBlePermissions()) { /* ... set ERROR_PERMISSIONS ... */ return }
        if (bluetoothLeAdvertiser == null || bluetoothAdapter?.isEnabled != true) { /* ... set ERROR_BLUETOOTH_OFF ... */ return }
        if (_isAdvertising.value) { /* ... log and return ... */ return }
        // ... (settings and data setup)
        val settings = AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM).setConnectable(true).build()
        val data = AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(ParcelUuid(BITCHAT_SERVICE_UUID)).build()
        try {
            Log.i(TAG, "Requesting to start LE Advertising.")
            bluetoothLeAdvertiser?.startAdvertising(settings, data, advertiseCallback)
        } catch (e: Exception) { /* ... log, set _isAdvertising false, set ERROR_GENERIC ... */
            Log.e(TAG, "Exception starting advertising: ${e.message}", e)
            _isAdvertising.value = false
            _bleOperationState.value = BleOperationState.ERROR_GENERIC
        }
    }

    @Synchronized
    fun stopAdvertising() {
        // ... (Permission and adapter checks)
        if (bluetoothLeAdvertiser == null && _isAdvertising.value) { /* ... force stop state ... */ return }
        if (!checkBlePermissions()) { /* ... log and return ... */ return }
        if (bluetoothLeAdvertiser == null || bluetoothAdapter?.isEnabled != true) { /* ... log and return ... */ return }
        if (!_isAdvertising.value) { /* ... log and return ... */ return }

        try {
            Log.i(TAG, "Requesting to stop LE Advertising.")
            bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
            _isAdvertising.value = false // Optimistic stop
            if (_bleOperationState.value == BleOperationState.ADVERTISING) _bleOperationState.value = BleOperationState.IDLE
        } catch (e: Exception) { /* ... log, set error state if applicable ... */
             Log.e(TAG, "Exception stopping advertising: ${e.message}", e)
             _isAdvertising.value = false // Ensure it's marked as stopped
             if (_bleOperationState.value == BleOperationState.ADVERTISING) _bleOperationState.value = BleOperationState.ERROR_GENERIC
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            _isAdvertising.value = true
            _bleOperationState.value = BleOperationState.ADVERTISING
            Log.i(TAG, "LE Advertising started successfully.")
        }
        override fun onStartFailure(errorCode: Int) {
            _isAdvertising.value = false
            _bleOperationState.value = BleOperationState.ERROR_GENERIC // Or more specific
            Log.e(TAG, "LE Advertising failed to start. Error Code: $errorCode")
        }
    }

    // --- Scanning ---
    @Synchronized
    fun startScanning() {
        // ... (Permission and adapter checks, then...)
        if (!checkBlePermissions()) { /* ... set ERROR_PERMISSIONS ... */ return }
        if (bluetoothLeScanner == null || bluetoothAdapter?.isEnabled != true) { /* ... set ERROR_BLUETOOTH_OFF ... */ return }
        if (_isScanning.value) { /* ... log and return ... */ return }
        // ... (filter and settings setup)
        val scanFilters: List<ScanFilter> = listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(BITCHAT_SERVICE_UUID)).build())
        val scanSettings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        try {
            Log.i(TAG, "Requesting to start LE Scan.")
            bluetoothLeScanner?.startScan(scanFilters, scanSettings, scanCallback)
            _bleOperationState.value = BleOperationState.SCANNING // Optimistic set
            _isScanning.value = true
        } catch (e: Exception) { /* ... log, set _isScanning false, set ERROR_GENERIC ... */
            Log.e(TAG, "Exception starting scan: ${e.message}", e)
            _isScanning.value = false
            _bleOperationState.value = BleOperationState.ERROR_GENERIC
        }
    }

     @Synchronized
    fun stopScanning() {
        // ... (Permission and adapter checks)
        if (bluetoothLeScanner == null && _isScanning.value) { /* ... force stop state ... */ return }
        if (!checkBlePermissions()) { /* ... log and return ... */ return }
        if (bluetoothLeScanner == null || bluetoothAdapter?.isEnabled != true) { /* ... log and return ... */ return }
        if (!_isScanning.value) { /* ... log and return ... */ return }
        try {
            Log.i(TAG, "Requesting to stop LE Scan.")
            bluetoothLeScanner?.stopScan(scanCallback)
            _isScanning.value = false // Optimistic stop
            if (_bleOperationState.value == BleOperationState.SCANNING) _bleOperationState.value = BleOperationState.IDLE
        } catch (e: Exception) { /* ... log, set error state if applicable ... */
            Log.e(TAG, "Exception stopping scan: ${e.message}", e)
            _isScanning.value = false
            if (_bleOperationState.value == BleOperationState.SCANNING) _bleOperationState.value = BleOperationState.ERROR_GENERIC
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val deviceName = try { if(checkBlePermissions()) result.device.name else "N/A" } catch (se: SecurityException) { "N/A (SecErr)" }
            Log.i(TAG, "Scan Result: Addr=${device.address}, Name=${deviceName ?: "N/A"}, RSSI=${result.rssi}")

            // Add to known peers or update lastSeen if already known
            val existingPeerInfo = knownPeers[device.address]
            if (existingPeerInfo == null) {
                knownPeers[device.address] = PeerConnectivityInfo(
                    deviceAddress = device.address,
                    bluetoothDevice = device,
                    connectionState = BleOperationState.IDLE, // Initial state before connection attempt
                    lastSeenTimestamp = System.currentTimeMillis()
                )
                Log.d(TAG, "New peer discovered: ${device.address}. Attempting connection.")
                connectToDevice(device) // Attempt to connect to newly discovered relevant peers
            } else {
                existingPeerInfo.lastSeenTimestamp = System.currentTimeMillis()
                existingPeerInfo.bluetoothDevice = device // Update device object in case it changed
                // If disconnected and not already reconnecting, try to reconnect to known good peers
                if (existingPeerInfo.isKnownGoodPeer && existingPeerInfo.connectionState is BleOperationState.IDLE || existingPeerInfo.connectionState is BleOperationState.ERROR_CONNECTION_FAILED) {
                     Log.d(TAG, "Known good peer ${device.address} found again. Attempting reconnection if needed.")
                     if(gattClientConnections[device.address] == null) { // check if not already connected or connecting
                        connectToDevice(device)
                     }
                }
            }
        }
        override fun onScanFailed(errorCode: Int) { /* ... set _isScanning false, set ERROR_GENERIC ... */
            _isScanning.value = false
            if (_bleOperationState.value == BleOperationState.SCANNING) _bleOperationState.value = BleOperationState.ERROR_GENERIC
            Log.e(TAG, "LE Scan failed. Error Code: $errorCode")
        }
    }

    // --- GATT Server ---
    @Synchronized
    private fun startGattServer() { /* ... (same as before, ensure logging and state updates) ... */
        if (!checkBlePermissions()) { _bleOperationState.value = BleOperationState.ERROR_PERMISSIONS; return }
        if (bluetoothAdapter?.isEnabled != true) { _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF; return }
        if (gattServer != null) { Log.d(TAG, "GATT Server already started."); return }
        try {
            gattServer = bluetoothManager.openGattServer(this, gattServerCallback)
            val service = BluetoothGattService(BITCHAT_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val characteristic = BluetoothGattCharacteristic(BITCHAT_CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE)
            characteristic.addDescriptor(BluetoothGattDescriptor(CLIENT_CHARACTERISTIC_CONFIG_UUID, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE))
            service.addCharacteristic(characteristic)
            if (gattServer?.addService(service) == true) Log.i(TAG, "GATT Server started, service added.")
            else { Log.e(TAG, "Failed to add service to GATT server."); gattServer?.close(); gattServer = null; _bleOperationState.value = BleOperationState.ERROR_GENERIC }
        } catch (e: Exception) { Log.e(TAG, "Exception starting GATT server: ${e.message}", e); gattServer = null; _bleOperationState.value = BleOperationState.ERROR_GENERIC }
    }
    @Synchronized
    private fun stopGattServer() { /* ... (same as before, ensure logging and state updates) ... */
        if (gattServer == null) { Log.d(TAG, "GATT Server not running."); return }
        try { gattServer?.close(); Log.i(TAG, "GATT Server stopped.") }
        catch (e: Exception) { Log.e(TAG, "Exception stopping GATT server: ${e.message}", e) }
        finally { gattServer = null; subscribedDevices.clear(); gattServerConnections.clear()
            // If advertising or scanning, those states should persist. If we were connected as server, revert to IDLE or active ops.
            if (_bleOperationState.value is BleOperationState.CONNECTED_AS_SERVER) {
                 if(_isAdvertising.value) _bleOperationState.value = BleOperationState.ADVERTISING
                 else if(_isScanning.value) _bleOperationState.value = BleOperationState.SCANNING
                 else _bleOperationState.value = BleOperationState.IDLE
            }
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            val deviceAddress = device.address
            val deviceName = try { if(checkBlePermissions()) device.name else "N/A" } catch (se: SecurityException) { "N/A (SecErr)" }
            Log.i(TAG, "GATT Server: Connection state change for $deviceAddress ($deviceName), Status: $status, NewState: $newState")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    gattServerConnections[deviceAddress] = device
                    knownPeers.compute(deviceAddress) { _, info ->
                        info?.copy(connectionState = BleOperationState.CONNECTED_AS_SERVER(deviceAddress, deviceName), bluetoothDevice = device, lastSeenTimestamp = System.currentTimeMillis())
                            ?: PeerConnectivityInfo(deviceAddress, device, BleOperationState.CONNECTED_AS_SERVER(deviceAddress, deviceName), System.currentTimeMillis())
                    }
                    _bleOperationState.value = BleOperationState.CONNECTED_AS_SERVER(deviceAddress, deviceName)
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    gattServerConnections.remove(deviceAddress)
                    subscribedDevices.remove(device)
                    knownPeers[deviceAddress]?.let { it.connectionState = BleOperationState.IDLE /* Or specific disconnected state */ }
                    if (gattServerConnections.isEmpty() && _bleOperationState.value is BleOperationState.CONNECTED_AS_SERVER) {
                         if(_isAdvertising.value) _bleOperationState.value = BleOperationState.ADVERTISING
                         else if(_isScanning.value) _bleOperationState.value = BleOperationState.SCANNING
                         else _bleOperationState.value = BleOperationState.IDLE
                    }
                }
            } else {
                Log.w(TAG, "GATT Server: Connection state error for $deviceAddress ($deviceName). Status: $status. Cleaning up.")
                gattServerConnections.remove(deviceAddress)
                subscribedDevices.remove(device)
                knownPeers[deviceAddress]?.let { it.connectionState = BleOperationState.ERROR_CONNECTION_FAILED(deviceAddress, status) }
                 if (_bleOperationState.value is BleOperationState.CONNECTED_AS_SERVER && ( (_bleOperationState.value as BleOperationState.CONNECTED_AS_SERVER).peerAddress == deviceAddress) ) {
                     _bleOperationState.value = BleOperationState.ERROR_CONNECTION_FAILED(deviceAddress, status)
                 }
            }
        }
        // ... (onCharacteristicReadRequest, onCharacteristicWriteRequest, onDescriptorWriteRequest with detailed logging and correct CCCD constant)
        override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            val dataSize = value?.size ?: 0
            Log.d(TAG, "GATT Server: Write request for Char ${characteristic.uuid.toString().takeLast(12)} from ${device.address}, Size: $dataSize bytes")
            if (BITCHAT_CHARACTERISTIC_UUID == characteristic.uuid && value != null) {
                handleReceivedRawData(value, device)
                if (responseNeeded) try { gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecEx sending write success resp to ${device.address}", se)}
            } else {
                if (responseNeeded) try { gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecEx sending write fail resp to ${device.address}", se)}
            }
        }
        override fun onDescriptorWriteRequest(device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
             if (descriptor.uuid == CLIENT_CHARACTERISTIC_CONFIG_UUID) { /* ... handle ENABLE/DISABLE, update subscribedDevices ... */
                var status = BluetoothGatt.GATT_SUCCESS
                if (Arrays.equals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, value)) {
                    Log.i(TAG, "GATT Server: Notifications ENABLED for ${descriptor.characteristic.uuid} by ${device.address}")
                    subscribedDevices.add(device)
                    knownPeers[device.address]?.wantsNotifications = true
                } else if (Arrays.equals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE, value)) {
                    Log.i(TAG, "GATT Server: Notifications DISABLED for ${descriptor.characteristic.uuid} by ${device.address}")
                    subscribedDevices.remove(device)
                    knownPeers[device.address]?.wantsNotifications = false
                } else { status = BluetoothGatt.GATT_WRITE_NOT_PERMITTED }
                if (responseNeeded) try { gattServer?.sendResponse(device, requestId, status, offset, value) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecEx sending desc write resp to ${device.address}", se)}
            } else if (responseNeeded) try { gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecEx sending desc write fail resp to ${device.address}", se)}
        }
        override fun onNotificationSent(device: BluetoothDevice, status: Int) { Log.d(TAG, "GATT Server: Notification sent to ${device.address}, Status: $status (Success=${status == BluetoothGatt.GATT_SUCCESS})") }
        override fun onServiceAdded(status: Int, service: BluetoothGattService?) { Log.i(TAG, "GATT Service ${service?.uuid?.toString()?.takeLast(12)} add status: $status (Success=${status == BluetoothGatt.GATT_SUCCESS})") }

    }

    // --- GATT Client & Reconnection Logic ---
    @Synchronized
    fun connectToDevice(device: BluetoothDevice, isReconnection: Boolean = false) {
        val deviceAddress = device.address
        if (!checkBlePermissions()) { _bleOperationState.value = BleOperationState.ERROR_PERMISSIONS; return }
        if (bluetoothAdapter?.isEnabled != true) { _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF; return }

        val peerInfo = knownPeers.computeIfAbsent(deviceAddress) {
            PeerConnectivityInfo(deviceAddress, device, BleOperationState.IDLE)
        }
        peerInfo.bluetoothDevice = device // Ensure device object is fresh

        if (gattClientConnections.containsKey(deviceAddress) && peerInfo.connectionState !is BleOperationState.ERROR_CONNECTION_FAILED && peerInfo.connectionState !is BleOperationState.IDLE) {
            Log.d(TAG, "GATT Client: Already connected or actively connecting to $deviceAddress. State: ${peerInfo.connectionState}")
            return
        }

        Log.i(TAG, "GATT Client: Requesting connection to $deviceAddress. IsReconnection: $isReconnection, Attempt: ${peerInfo.reconnectionAttempts + 1}")
        _bleOperationState.value = if(isReconnection) BleOperationState.RECONNECTING_TO_PEER(deviceAddress, peerInfo.reconnectionAttempts + 1)
                                 else BleOperationState.CONNECTING_TO_PEER(deviceAddress)
        peerInfo.connectionState = _bleOperationState.value // Update peer's specific state

        serviceScope.launch {
            try {
                // Timeout for the connection attempt itself
                val gatt = withTimeoutOrNull(CONNECTION_TIMEOUT_MS) {
                    suspendCancellableCoroutine<BluetoothGatt?> { continuation ->
                        val gattInstance = device.connectGatt(this@BluetoothMeshService, false, gattClientCallback, BluetoothDevice.TRANSPORT_LE)
                        if (gattInstance == null) {
                            Log.e(TAG, "GATT Client: device.connectGatt returned null for $deviceAddress immediately.")
                            continuation.resume(null, null)
                        } else {
                            // Don't store in gattClientConnections yet, wait for onConnectionStateChange
                            // Store a reference to the continuation to resume it from the callback
                            activeGattContinuations[device.address] = continuation
                            continuation.invokeOnCancellation {
                                Log.w(TAG, "GATT Client: Connection attempt to $deviceAddress cancelled or timed out before callback.")
                                activeGattContinuations.remove(device.address)
                                try { if (checkBlePermissions()) gattInstance.close() } catch (e: Exception) { Log.e(TAG, "Error closing GATT on cancellation for $deviceAddress", e) }
                            }
                        }
                    }
                }

                if (gatt == null && activeGattContinuations.containsKey(device.address)) { // Timeout likely occurred before onConnectionStateChange made it connected
                    Log.w(TAG, "GATT Client: Connection attempt to $deviceAddress timed out (${CONNECTION_TIMEOUT_MS}ms).")
                    activeGattContinuations.remove(device.address)?.resume(null,null) // Ensure coroutine is unblocked
                    handleConnectionFailure(deviceAddress, BluetoothGatt.GATT_FAILURE, isTimeout = true)
                } else if (gatt == null && !activeGattContinuations.containsKey(device.address)) {
                    // This means connectGatt itself returned null or some other immediate failure
                     handleConnectionFailure(deviceAddress, BluetoothGatt.GATT_FAILURE, isTimeout = false)
                }
                // Success is handled in onConnectionStateChange
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "GATT Client: Connection attempt to $deviceAddress timed out EXCEPTION (${CONNECTION_TIMEOUT_MS}ms).")
                handleConnectionFailure(deviceAddress, BluetoothGatt.GATT_FAILURE, isTimeout = true)
            } catch (se: SecurityException) {
                Log.e(TAG, "GATT Client: SecurityException on connectGatt for $deviceAddress: ${se.message}", se)
                handleConnectionFailure(deviceAddress, BluetoothGatt.GATT_FAILURE) // Generic failure status
            } catch (e: Exception) {
                Log.e(TAG, "GATT Client: Exception during connectToDevice for $deviceAddress: ${e.message}", e)
                handleConnectionFailure(deviceAddress, BluetoothGatt.GATT_FAILURE)
            }
        }
    }
    // Store continuations for connectGatt
    private val activeGattContinuations = ConcurrentHashMap<String, CancellableContinuation<BluetoothGatt?>>()


    private fun handleConnectionFailure(deviceAddress: String, status: Int, isTimeout: Boolean = false) {
        Log.w(TAG, "GATT Client: Handling connection failure for $deviceAddress. Status: $status, Timeout: $isTimeout")
        gattClientConnections.remove(deviceAddress)?.apply { try { if (checkBlePermissions()) close() } catch (e: Exception) {} }

        val peerInfo = knownPeers[deviceAddress]
        if (peerInfo != null) {
            peerInfo.connectionState = BleOperationState.ERROR_CONNECTION_FAILED(deviceAddress, status, isTimeout)
            _bleOperationState.value = peerInfo.connectionState // Update global state if this was the active attempt
            if (peerInfo.isKnownGoodPeer) { // Only try to reconnect known good peers
                scheduleReconnection(peerInfo)
            }
        } else {
             // If peerInfo is null, it was a first attempt and failed. Update global state.
            _bleOperationState.value = BleOperationState.ERROR_CONNECTION_FAILED(deviceAddress, status, isTimeout)
        }
    }

    private fun scheduleReconnection(peerInfo: PeerConnectivityInfo) {
        if (peerInfo.reconnectionAttempts >= MAX_RECONNECTION_ATTEMPTS) {
            Log.w(TAG, "Max reconnection attempts reached for ${peerInfo.deviceAddress}. Giving up.")
            peerInfo.connectionState = BleOperationState.ERROR_CONNECTION_FAILED(peerInfo.deviceAddress, null, false) // Mark as terminally failed for now
            // Could update _bleOperationState here if this was the primary peer being focused on.
            return
        }

        val delayTime = (INITIAL_RECONNECTION_DELAY_MS * (2.0.pow(peerInfo.reconnectionAttempts))).toLong().coerceAtMost(MAX_RECONNECTION_DELAY_MS)
        Log.i(TAG, "Scheduling reconnection attempt ${peerInfo.reconnectionAttempts + 1} for ${peerInfo.deviceAddress} in ${delayTime}ms.")

        serviceScope.launch {
            delay(delayTime)
            // Check if still relevant to reconnect (e.g., service not destroyed, BT on)
            if (isActive && bluetoothAdapter?.isEnabled == true && checkBlePermissions()) {
                 peerInfo.bluetoothDevice?.let {
                    Log.d(TAG, "Executing scheduled reconnection for ${it.address}")
                    peerInfo.reconnectionAttempts++
                    connectToDevice(it, isReconnection = true)
                } ?: Log.w(TAG, "Cannot execute scheduled reconnection for ${peerInfo.deviceAddress}, BluetoothDevice object is null.")
            } else {
                Log.w(TAG, "Skipping scheduled reconnection for ${peerInfo.deviceAddress}: Service inactive, BT off, or permissions lost.")
            }
        }
    }


    @Synchronized
    fun disconnectFromDevice(deviceAddress: String) { /* ... (same as before, ensure logging and state updates) ... */
        if (!_connectedGattClientDevices.value.containsKey(deviceAddress) && !gattClientConnections.containsKey(deviceAddress)) {
             Log.w(TAG, "GATT Client: Cannot disconnect, no active or pending GATT client for $deviceAddress")
            return
        }
        Log.i(TAG, "GATT Client: Requesting disconnect from $deviceAddress")
        // Try to get from established connections first, then from pending (if any were stored optimistically)
        val gattToDisconnect = gattClientConnections[deviceAddress] ?: _connectedGattClientDevices.value[deviceAddress]

        gattToDisconnect?.let { gatt ->
            try {
                if (checkBlePermissions()) gatt.disconnect() // Callback will handle close and removal from map
                else { // If no perms, can't call disconnect, so clean up locally
                    Log.w(TAG, "GATT Client: No BLUETOOTH_CONNECT perm to disconnect $deviceAddress. Closing locally.")
                    gatt.close()
                    gattClientConnections.remove(deviceAddress)
                    knownPeers[deviceAddress]?.connectionState = BleOperationState.IDLE
                     if (_bleOperationState.value is BleOperationState.CONNECTED_AS_CLIENT && (_bleOperationState.value as BleOperationState.CONNECTED_AS_CLIENT).peerAddress == deviceAddress) {
                        _bleOperationState.value = BleOperationState.IDLE
                    }
                }
            } catch (se: SecurityException) {
                 Log.e(TAG, "GATT Client: SecurityException on disconnect for $deviceAddress: ${se.message}", se)
                gatt.close() // Best effort close
                gattClientConnections.remove(deviceAddress)
                knownPeers[deviceAddress]?.connectionState = BleOperationState.IDLE
                 if (_bleOperationState.value is BleOperationState.CONNECTED_AS_CLIENT && (_bleOperationState.value as BleOperationState.CONNECTED_AS_CLIENT).peerAddress == deviceAddress) {
                    _bleOperationState.value = BleOperationState.IDLE
                }
            }
        }
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val deviceAddress = gatt.device.address
            val deviceName = try { if(checkBlePermissions()) gatt.device.name else "N/A" } catch (se: SecurityException) { "N/A (SecErr)" }
            Log.i(TAG, "GATT Client: Connection state change for $deviceAddress ($deviceName), Status: $status, NewState: $newState")

            activeGattContinuations.remove(deviceAddress)?.resume(if(newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) gatt else null, null)

            val peerInfo = knownPeers.computeIfAbsent(deviceAddress) {
                PeerConnectivityInfo(deviceAddress, gatt.device, BleOperationState.IDLE)
            }
            peerInfo.bluetoothDevice = gatt.device // Update with fresh device object

            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    gattClientConnections[deviceAddress] = gatt // Store successful GATT connection
                    peerInfo.connectionState = BleOperationState.CONNECTED_AS_CLIENT(deviceAddress, deviceName)
                    peerInfo.reconnectionAttempts = 0 // Reset on successful connection
                    peerInfo.isKnownGoodPeer = true
                    _bleOperationState.value = peerInfo.connectionState
                    serviceScope.launch {
                        delay(600)
                        Log.d(TAG, "GATT Client: Discovering services for $deviceAddress...")
                        try { if(checkBlePermissions()) gatt.discoverServices() else Log.e(TAG, "No CONNECT perm for discoverServices on $deviceAddress") }
                        catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc on discoverServices for $deviceAddress", se)}
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    Log.i(TAG, "GATT Client: Successfully DISCONNECTED from $deviceAddress ($deviceName)")
                    try { if(checkBlePermissions()) gatt.close() } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc on gatt.close for $deviceAddress ($deviceName)", se) }
                    gattClientConnections.remove(deviceAddress)
                    peerInfo.connectionState = BleOperationState.IDLE // Or a specific "Disconnected" state
                    if ((_bleOperationState.value is BleOperationState.CONNECTED_AS_CLIENT && (_bleOperationState.value as BleOperationState.CONNECTED_AS_CLIENT).peerAddress == deviceAddress) ||
                        (_bleOperationState.value is BleOperationState.CONNECTING_TO_PEER && (_bleOperationState.value as BleOperationState.CONNECTING_TO_PEER).peerAddress == deviceAddress) ||
                        (_bleOperationState.value is BleOperationState.RECONNECTING_TO_PEER && (_bleOperationState.value as BleOperationState.RECONNECTING_TO_PEER).peerAddress == deviceAddress)
                    ) {
                        if (peerInfo.isKnownGoodPeer) { // Check if it was a known good peer that disconnected unexpectedly
                             Log.w(TAG, "Known good peer $deviceAddress ($deviceName) disconnected. Scheduling reconnections.")
                             scheduleReconnection(peerInfo) // Schedule reconnections for known good peers
                         } else {
                            if (_isAdvertising.value) _bleOperationState.value = BleOperationState.ADVERTISING
                            else if (_isScanning.value) _bleOperationState.value = BleOperationState.SCANNING
                            else _bleOperationState.value = BleOperationState.IDLE
                         }
                    }
                }
            } else {
                Log.e(TAG, "GATT Client: Connection attempt FAILED for $deviceAddress ($deviceName). Status: $status. Cleaning up.")
                try { if(checkBlePermissions()) gatt.close() } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc on gatt.close after error for $deviceAddress ($deviceName)", se) }
                gattClientConnections.remove(deviceAddress)
                handleConnectionFailure(deviceAddress, status)
            }
        }
        // ... (onServicesDiscovered, onCharacteristicRead, onCharacteristicWrite, onCharacteristicChanged, onDescriptorWrite with detailed logging)
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) { /* ... existing logging + enableNotifications ... */
            val deviceAddress = gatt.device.address; Log.d(TAG, "GATT Client: onServicesDiscovered for $deviceAddress, Status: $status")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                gatt.getService(BITCHAT_SERVICE_UUID)?.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)?.let { char ->
                    enableNotificationsOnCharacteristic(gatt, char)
                } ?: Log.w(TAG, "GATT Client: BitChat service/char NOT FOUND on $deviceAddress after discovery.")
            } else Log.w(TAG, "GATT Client: Service discovery FAILED for $deviceAddress, status: $status")
        }
        override fun onCharacteristicRead(gatt: BluetoothGatt, c: BluetoothGattCharacteristic, v: ByteArray, s: Int) { if(s == BluetoothGatt.GATT_SUCCESS && c.uuid == BITCHAT_CHARACTERISTIC_UUID) handleReceivedRawData(v, gatt.device) }
        override fun onCharacteristicWrite(gatt: BluetoothGatt, c: BluetoothGattCharacteristic, s: Int) { Log.d(TAG, "GATT Client: Write to ${c.uuid.toString().takeLast(6)} on ${gatt.device.address} status: $s (Success=${s==BluetoothGatt.GATT_SUCCESS})")}
        override fun onCharacteristicChanged(gatt: BluetoothGatt, c: BluetoothGattCharacteristic, v: ByteArray) { if(c.uuid == BITCHAT_CHARACTERISTIC_UUID) handleReceivedRawData(v, gatt.device)}
        override fun onDescriptorWrite(gatt: BluetoothGatt, d: BluetoothGattDescriptor, s: Int) { Log.d(TAG, "GATT Client: DescWrite ${d.uuid.toString().takeLast(6)} on ${gatt.device.address} status: $s (Success=${s==BluetoothGatt.GATT_SUCCESS})")}
    }

    // --- Data Handling & Sending ---
    private fun handleReceivedRawData(rawData: ByteArray, fromDevice: BluetoothDevice) { /* ... (same as before) ... */
        Log.i(TAG, "Handling ${rawData.size} raw bytes from ${fromDevice.address}")
        val encryptionService = EncryptionService()
        val packet = BinaryProtocol.deserializePacket(rawData, encryptionService)
        if (packet != null) {
            Log.i(TAG, "Deserialized Packet ID ${packet.id} from ${packet.sourceId} (Device: ${fromDevice.address})")
            serviceScope.launch { _processedReceivedPacketsFlow.emit(packet) }
        } else { Log.w(TAG, "Failed to deserialize packet from ${fromDevice.address}. Raw (hex): ${rawData.joinToString("") { "%02x".format(it) }}") }
    }

    fun sendDataToPeers(serializedPacket: ByteArray, originalPacket: BitchatPacket) { /* ... (same as before, ensure logging) ... */
        if (!checkBlePermissions()) { Log.e(TAG, "Cannot send packet ${originalPacket.id}: Permissions missing."); return }
        if (serializedPacket.isEmpty()) { Log.w(TAG, "Cannot send empty data for packet ${originalPacket.id}."); return }
        Log.i(TAG, "Queueing send for packet ${originalPacket.id} (${serializedPacket.size} bytes).")

        var sentToAtLeastOnePeer = false
        // GATT Server: Notify subscribed devices
        val serverConnected = gattServerConnections.values.filter { subscribedDevices.contains(it) }
        serverConnected.forEach { device ->
            gattServer?.getService(BITCHAT_SERVICE_UUID)?.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)?.let { char ->
                serviceScope.launch { // Ensure notifications are on IO dispatcher
                    Log.d(TAG, "GATT Server: Notifying ${device.address} with packet ${originalPacket.id}.")
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        try { gattServer?.notifyCharacteristicChanged(device, char, false, serializedPacket) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecEx notify for ${device.address}", se)}
                    } else {
                        char.value = serializedPacket
                        try { gattServer?.notifyCharacteristicChanged(device, char, false) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecEx notify for ${device.address}", se)}
                    }
                    sentToAtLeastOnePeer = true
                }
            }
        }
        // GATT Client: Write to connected characteristics
        gattClientConnections.values.forEach { gatt ->
            gatt.getService(BITCHAT_SERVICE_UUID)?.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)?.let { char ->
                val writeType = if ((char.properties and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE) != 0) BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE else BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                serviceScope.launch {
                    Log.d(TAG, "GATT Client: Writing packet ${originalPacket.id} to ${gatt.device.address} (type $writeType).")
                    val success = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        try { gatt.writeCharacteristic(char, serializedPacket, writeType) == BluetoothStatusCodes.SUCCESS } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecEx writing to ${gatt.device.address}", se); false }
                    } else {
                        char.value = serializedPacket; char.writeType = writeType
                        try { gatt.writeCharacteristic(char) } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecEx writing to ${gatt.device.address}", se); false }
                    }
                    if (success) sentToAtLeastOnePeer = true
                    else Log.w(TAG, "GATT Client: Failed write to ${gatt.device.address} for packet ${originalPacket.id}")
                }
            }
        }
        if (!sentToAtLeastOnePeer) Log.w(TAG, "Packet ${originalPacket.id} not sent to any peer (no suitable connections/subscriptions).")
    }

    private fun enableNotificationsOnCharacteristic(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) { /* ... (same as before, ensure logging) ... */
         if (!checkBlePermissions()) { Log.e(TAG, "GATT Client: NoPerms to enable notifications for ${characteristic.uuid} on ${gatt.device.address}"); return }
        if ((characteristic.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) == 0) { Log.w(TAG, "GATT Client: Char ${characteristic.uuid} on ${gatt.device.address} no NOTIFY"); return }
        val cccd = characteristic.getDescriptor(CLIENT_CHARACTERISTIC_CONFIG_UUID)
        if (cccd == null) { Log.w(TAG, "GATT Client: No CCCD for char ${characteristic.uuid} on ${gatt.device.address}"); return }
        Log.d(TAG, "GATT Client: Enabling notifications for ${characteristic.uuid} on ${gatt.device.address}")
        try {
            if(checkBlePermissions()) gatt.setCharacteristicNotification(characteristic, true) else { Log.e(TAG, "No CONNECT perm for setCharacteristicNotification"); return }
            val writeSuccess : Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if(checkBlePermissions()) gatt.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS else false
            } else {
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                if(checkBlePermissions()) gatt.writeDescriptor(cccd) else false
            }
            if (!writeSuccess) {Log.w(TAG, "GATT Client: Failed write CCCD for notifications on ${gatt.device.address}. Reverting local."); if(checkBlePermissions()) gatt.setCharacteristicNotification(characteristic, false) }
            else { knownPeers[gatt.device.address]?.wantsNotifications = true } // Assuming client is a known peer
        } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecEx enabling notifications for ${gatt.device.address}", se); try { if(checkBlePermissions()) gatt.setCharacteristicNotification(characteristic, false) } catch (e: Exception) {} }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "Service onDestroy. Instance: ${this.hashCode()}. Cleaning up BLE resources.")
        serviceScope.cancel()
        stopAdvertising()
        stopScanning()
        stopGattServer()

        gattClientConnections.values.forEach { gatt ->
            try { if (checkBlePermissions()) gatt.close() }
            catch (e: Exception) { Log.e(TAG, "Exception closing client GATT on destroy for ${gatt.device.address}", e) }
        }
        gattClientConnections.clear()
        knownPeers.clear()

        try { stopForeground(true) }
        catch (e: Exception) { Log.e(TAG, "Exception stopping foreground service: ${e.message}", e) }
        Log.i(TAG, "Service destroyed and BLE resources released.")
    }
}

[end of app/src/main/java/com/example/bitchat/services/BluetoothMeshService.kt]
