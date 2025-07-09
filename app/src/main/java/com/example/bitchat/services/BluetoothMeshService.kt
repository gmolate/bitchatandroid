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
import com.example.bitchat.models.BinaryProtocol // Assuming BinaryProtocol is accessible for deserialization
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import java.util.*
import kotlin.collections.HashMap

class BluetoothMeshService : Service() {

    private val binder = LocalBinder()
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private lateinit var bluetoothManager: BluetoothManager
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothLeScanner: BluetoothLeScanner? = null
    private var bluetoothLeAdvertiser: BluetoothLeAdvertiser? = null
    private var gattServer: BluetoothGattServer? = null

    // --- Bluetooth State Flows ---
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _isAdvertising = MutableStateFlow(false)
    val isAdvertising: StateFlow<Boolean> = _isAdvertising.asStateFlow()

    private val _connectedGattServerDevices = MutableStateFlow<Map<String, BluetoothDevice>>(emptyMap()) // Devices connected TO our GATT Server
    val connectedGattServerDevices: StateFlow<Map<String, BluetoothDevice>> = _connectedGattServerDevices.asStateFlow()

    private val _connectedGattClientDevices = MutableStateFlow<Map<String, BluetoothGatt>>(emptyMap()) // Devices WE are connected TO as a GATT Client
    val connectedGattClientDevices: StateFlow<Map<String, BluetoothGatt>> = _connectedGattClientDevices.asStateFlow()

    private val _processedReceivedPacketsFlow = MutableSharedFlow<BitchatPacket>(
        replay = 0,
        extraBufferCapacity = 64, // Buffer up to 64 packets
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val processedReceivedPacketsFlow: SharedFlow<BitchatPacket> = _processedReceivedPacketsFlow.asSharedFlow()

    // Map to keep track of devices that have enabled notifications on our GATT server
    private val subscribedDevices = Collections.synchronizedSet(HashSet<BluetoothDevice>())


    companion object {
        private const val TAG = "BTMeshService" // Shortened TAG for better logcat readability
        private const val NOTIFICATION_CHANNEL_ID = "BitChatServiceChannel"
        private const val NOTIFICATION_ID = 101

        val BITCHAT_SERVICE_UUID: UUID = UUID.fromString("0000b17c-0000-1000-8000-00805f9b34fb")
        val BITCHAT_CHARACTERISTIC_UUID: UUID = UUID.fromString("0000b17d-0000-1000-8000-00805f9b34fb")
        val CLIENT_CHARACTERISTIC_CONFIG_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    inner class LocalBinder : Binder() {
        fun getService(): BluetoothMeshService = this@BluetoothMeshService
    }

    override fun onBind(intent: Intent): IBinder {
        Log.d(TAG, "Service onBind")
        return binder
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Service onCreate")
        bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth not supported on this device. Stopping service.")
            stopSelf()
            return
        }
        if (!bluetoothAdapter!!.isEnabled) {
            Log.w(TAG, "Bluetooth is not enabled. Operations will fail until enabled.")
            // Consider broadcasting an intent or using a callback to inform UI to prompt user.
        }

        bluetoothLeScanner = bluetoothAdapter?.bluetoothLeScanner
        bluetoothLeAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser

        createNotificationChannel()
        Log.i(TAG, "Service created successfully.")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "Service onStartCommand, Intent Action: ${intent?.action}")
        startForeground(NOTIFICATION_ID, createNotification())

        if (checkBlePermissions()) {
            Log.d(TAG, "BLE permissions granted. Initializing BLE operations.")
            initializeBleOperations()
        } else {
            Log.w(TAG, "BLE permissions not granted. Cannot start BLE operations. Waiting for permissions.")
            // UI should handle requesting permissions. Service will wait.
        }
        return START_STICKY
    }

    fun initializeBleOperations() {
        if (!checkBlePermissions()) {
            Log.w(TAG, "Attempted to initialize BLE operations, but permissions are still missing.")
            return
        }
        Log.i(TAG, "Initializing BLE operations: GATT Server, Advertising, Scanning.")
        serviceScope.launch { // Launch on service's IO scope
            startGattServer()
            startAdvertising()
            startScanning()
        }
    }


    private fun checkBlePermissions(): Boolean {
        val requiredPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE
            )
        } else {
            listOf(
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN,
                Manifest.permission.ACCESS_FINE_LOCATION // Needed for scanning pre-S
            )
        }
        // ACCESS_FINE_LOCATION is often still needed for reliable scan results on S+ if not using `neverForLocation`
        // and even then, some devices behave better with it.
        val allRequired = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            requiredPermissions // Fine location already included
        } else {
            requiredPermissions + Manifest.permission.ACCESS_FINE_LOCATION
        }


        val missingPermissions = allRequired.filter {
            ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isNotEmpty()) {
            Log.w(TAG, "Missing BLE permissions: $missingPermissions")
            return false
        }
        Log.d(TAG, "All required BLE permissions are granted.")
        return true
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "BitChat Background Service",
                NotificationManager.IMPORTANCE_LOW // Use LOW to avoid sound/vibration by default
            ).apply {
                description = "BitChat BLE communication service"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(serviceChannel)
            Log.d(TAG, "Notification channel created.")
        }
    }

    private fun createNotification(): Notification {
        val notificationIntent = Intent(this, MainActivity::class.java) // Ensure MainActivity is correct
        val pendingIntentFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, pendingIntentFlags)

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("BitChat Active")
            .setContentText("Mesh networking service is running.")
            .setSmallIcon(R.drawable.ic_bitchat_notification) // Ensure this drawable exists
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    // --- Advertising ---
    @Synchronized
    fun startAdvertising() {
        if (!checkBlePermissions() || bluetoothLeAdvertiser == null) {
            Log.e(TAG, "Cannot start advertising: Permissions missing or advertiser not available.")
            _isAdvertising.value = false
            return
        }
        if (_isAdvertising.value) {
            Log.d(TAG, "Advertising is already active.")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false) // Consider privacy
            .addServiceUuid(ParcelUuid(BITCHAT_SERVICE_UUID))
            .build()
        try {
            bluetoothLeAdvertiser?.startAdvertising(settings, data, advertiseCallback)
            // _isAdvertising.value will be set true in onStartSuccess
            Log.i(TAG, "Advertising start requested with Service UUID: $BITCHAT_SERVICE_UUID")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException starting advertising: ${e.message}", e)
            _isAdvertising.value = false
        } catch (e: IllegalStateException) {
            Log.e(TAG, "IllegalStateException starting advertising (e.g., BT off): ${e.message}", e)
            _isAdvertising.value = false
        }
    }

    @Synchronized
    fun stopAdvertising() {
        if (!checkBlePermissions() || bluetoothLeAdvertiser == null) {
            Log.e(TAG, "Cannot stop advertising: Permissions missing or advertiser not available (or BT off).")
            return
        }
        if (!_isAdvertising.value) {
            Log.d(TAG, "Not currently advertising.")
            return
        }
        try {
            bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
            _isAdvertising.value = false // Assume stop is immediate, callback might not always fire quickly
            Log.i(TAG, "Advertising stop requested.")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException stopping advertising: ${e.message}", e)
        } catch (e: IllegalStateException) {
            Log.e(TAG, "IllegalStateException stopping advertising (e.g., BT off): ${e.message}", e)
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            _isAdvertising.value = true
            Log.i(TAG, "LE Advertising started successfully. Settings: $settingsInEffect")
        }

        override fun onStartFailure(errorCode: Int) {
            _isAdvertising.value = false
            Log.e(TAG, "LE Advertising failed to start. Error Code: $errorCode. See AdvertiseCallback docs for details.")
        }
    }

    // --- Scanning ---
    @Synchronized
    fun startScanning() {
        if (!checkBlePermissions() || bluetoothLeScanner == null) {
            Log.e(TAG, "Cannot start scanning: Permissions missing or scanner not available.")
            _isScanning.value = false
            return
        }
        if (_isScanning.value) {
            Log.d(TAG, "Scanning is already active.")
            return
        }
        val scanFilters: List<ScanFilter> = listOf(
            ScanFilter.Builder().setServiceUuid(ParcelUuid(BITCHAT_SERVICE_UUID)).build()
        )
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        try {
            bluetoothLeScanner?.startScan(scanFilters, scanSettings, scanCallback)
            _isScanning.value = true
            Log.i(TAG, "Scanning started for Service UUID: $BITCHAT_SERVICE_UUID")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException starting scan: ${e.message}", e)
            _isScanning.value = false
        } catch (e: IllegalStateException) {
            Log.e(TAG, "IllegalStateException starting scan (e.g., BT off): ${e.message}", e)
            _isScanning.value = false
        }
    }

    @Synchronized
    fun stopScanning() {
        if (!checkBlePermissions() || bluetoothLeScanner == null) {
            Log.e(TAG, "Cannot stop scanning: Permissions missing or scanner not available (or BT off).")
            return
        }
        if (!_isScanning.value) {
            Log.d(TAG, "Not currently scanning.")
            return
        }
        try {
            bluetoothLeScanner?.stopScan(scanCallback)
            _isScanning.value = false
            Log.i(TAG, "Scanning stopped.")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException stopping scan: ${e.message}", e)
        } catch (e: IllegalStateException) {
            Log.e(TAG, "IllegalStateException stopping scan (e.g., BT off): ${e.message}", e)
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val deviceName = try { if(checkBlePermissions()) result.device.name else "N/A" } catch (se: SecurityException) { "N/A (SecErr)" }
            Log.d(TAG, "Scan Result: Addr=${device.address}, Name=${deviceName ?: "N/A"}, RSSI=${result.rssi}, Data=${result.scanRecord?.bytes?.let { it.size.toString() + " bytes" } ?: "N/A"}")
            // TODO: Connect logic, possibly based on device properties or if it's a new device.
            // connectToDevice(device) // Example: connect to any discovered device advertising our service.
        }

        override fun onBatchScanResults(results: List<ScanResult>) {
            Log.d(TAG, "Batch Scan Results: ${results.size} devices found.")
            results.forEach { result ->
                 val deviceName = try { if(checkBlePermissions()) result.device.name else "N/A" } catch (se: SecurityException) { "N/A (SecErr)" }
                Log.d(TAG, "  Batch Device: Addr=${result.device.address}, Name=${deviceName ?: "N/A"}, RSSI=${result.rssi}")
            }
        }

        override fun onScanFailed(errorCode: Int) {
            _isScanning.value = false
            Log.e(TAG, "Scan Failed. Error Code: $errorCode. See ScanCallback docs for details.")
        }
    }

    // --- GATT Server ---
    @Synchronized
    private fun startGattServer() {
        if (!checkBlePermissions() || bluetoothAdapter == null) { // Adapter check added
            Log.e(TAG, "Cannot start GATT server: Permissions missing or BluetoothAdapter not available.")
            return
        }
        if (gattServer != null) {
            Log.d(TAG, "GATT Server already started.")
            return
        }
        try {
            gattServer = bluetoothManager.openGattServer(this, gattServerCallback)
            val service = BluetoothGattService(BITCHAT_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val characteristic = BluetoothGattCharacteristic(
                BITCHAT_CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            val cccd = BluetoothGattDescriptor(CLIENT_CHARACTERISTIC_CONFIG_UUID, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE)
            characteristic.addDescriptor(cccd)
            service.addCharacteristic(characteristic)

            val serviceAdded = gattServer?.addService(service)
            if (serviceAdded == true) {
                Log.i(TAG, "GATT Server started and BitChat service added successfully.")
            } else {
                 Log.e(TAG, "Failed to add BitChat service to GATT server.")
                 gattServer?.close() // Clean up
                 gattServer = null
            }
        } catch (se: SecurityException) {
            Log.e(TAG, "SecurityException starting GATT server: ${se.message}", se)
            gattServer = null
        }
    }

    @Synchronized
    private fun stopGattServer() {
        if (gattServer == null) {
            Log.d(TAG, "GATT Server not running or already stopped.")
            return
        }
        try {
            gattServer?.close()
            Log.i(TAG, "GATT Server stopped.")
        } catch (se: SecurityException) {
            // Though close() itself doesn't list SecurityException, good to be cautious
            Log.e(TAG, "SecurityException stopping GATT server: ${se.message}", se)
        } finally {
            gattServer = null
            subscribedDevices.clear()
            _connectedGattServerDevices.value = emptyMap()
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            val deviceAddress = device.address
            Log.d(TAG, "GATT Server: onConnectionStateChange from $deviceAddress, Status: $status, NewState: $newState")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    Log.i(TAG, "GATT Server: Device Connected - $deviceAddress")
                    _connectedGattServerDevices.update { it + (deviceAddress to device) }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    Log.i(TAG, "GATT Server: Device Disconnected - $deviceAddress")
                    _connectedGattServerDevices.update { it - deviceAddress }
                    subscribedDevices.remove(device)
                }
            } else {
                Log.w(TAG, "GATT Server: Connection state error for $deviceAddress. Status: $status, NewState: $newState")
                _connectedGattServerDevices.update { it - deviceAddress }
                subscribedDevices.remove(device)
            }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic) {
            Log.d(TAG, "GATT Server: Read request for Char ${characteristic.uuid.toString().takeLast(12)} from ${device.address}, Offset: $offset")
            if (BITCHAT_CHARACTERISTIC_UUID == characteristic.uuid) {
                // TODO: Provide actual data based on characteristic. For now, a placeholder.
                val dataToSend = "BitChatServerSaysHello".toByteArray(Charsets.UTF_8)
                val responseData = if (offset >= dataToSend.size) ByteArray(0) else dataToSend.copyOfRange(offset, dataToSend.size)
                try {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, responseData)
                    Log.d(TAG, "GATT Server: Sent read response (${responseData.size} bytes) to ${device.address}")
                } catch (se: SecurityException) { Log.e(TAG, "GATT Server: SecurityExc sending read response to ${device.address}", se)}
            } else {
                Log.w(TAG, "GATT Server: Read request for unknown characteristic ${characteristic.uuid}")
                try { gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecurityExc sending read failure response to ${device.address}", se)}
            }
        }

        override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            val dataSize = value?.size ?: 0
            Log.d(TAG, "GATT Server: Write request for Char ${characteristic.uuid.toString().takeLast(12)} from ${device.address}, Size: $dataSize bytes, Offset: $offset, Prepared: $preparedWrite, RespNeeded: $responseNeeded")
            if (BITCHAT_CHARACTERISTIC_UUID == characteristic.uuid && value != null) {
                // TODO: Handle potential fragmentation if data is large, or rely on MTU negotiation.
                Log.i(TAG, "GATT Server: Received ${value.size} bytes on BitChat characteristic from ${device.address}")
                handleReceivedRawData(value, device) // Process the data

                if (responseNeeded) {
                    try {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                        Log.d(TAG, "GATT Server: Sent write success response to ${device.address}")
                    } catch (se: SecurityException) { Log.e(TAG, "GATT Server: SecurityExc sending write success response to ${device.address}", se)}
                }
            } else {
                Log.w(TAG, "GATT Server: Write request for unknown characteristic or null value.")
                if (responseNeeded) {
                    try { gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecurityExc sending write failure response to ${device.address}", se)}
                }
            }
        }

        override fun onDescriptorWriteRequest(device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            Log.d(TAG, "GATT Server: DescWrite for ${descriptor.uuid.toString().takeLast(12)} from ${device.address}, Value: ${value?.contentToString()}")
            if (descriptor.uuid == CLIENT_CHARACTERISTIC_CONFIG_UUID) {
                var status = BluetoothGatt.GATT_SUCCESS
                if (Arrays.equals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, value)) {
                    Log.i(TAG, "GATT Server: Notifications ENABLED for ${descriptor.characteristic.uuid} by ${device.address}")
                    subscribedDevices.add(device)
                } else if (Arrays.equals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE, value)) {
                    Log.i(TAG, "GATT Server: Notifications DISABLED for ${descriptor.characteristic.uuid} by ${device.address}")
                    subscribedDevices.remove(device)
                } else {
                    Log.w(TAG, "GATT Server: Unknown value written to CCCD: ${value?.contentToString()}")
                    status = BluetoothGatt.GATT_WRITE_NOT_PERMITTED
                }
                if (responseNeeded) {
                    try { gattServer?.sendResponse(device, requestId, status, offset, value) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecurityExc sending desc write response to ${device.address}", se)}
                }
            } else {
                Log.w(TAG, "GATT Server: Write request for unknown descriptor ${descriptor.uuid}")
                if (responseNeeded) {
                    try { gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null) } catch (se: SecurityException) {Log.e(TAG, "GATT Server: SecurityExc sending desc write failure response to ${device.address}", se)}
                }
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            Log.d(TAG, "GATT Server: Notification sent to ${device.address}, Status: $status")
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.w(TAG, "GATT Server: Failed to send notification to ${device.address}, Status: $status")
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Service ${service?.uuid?.toString()?.takeLast(12)} added successfully.")
            } else {
                Log.e(TAG, "GATT Service addition failed with status: $status. Service UUID: ${service?.uuid}")
            }
        }
    }

    // --- GATT Client ---
    // `connectedGattClientDevices` StateFlow now holds BluetoothGatt objects

    @Synchronized
    fun connectToDevice(device: BluetoothDevice) {
        if (!checkBlePermissions()) {
            Log.e(TAG, "GATT Client: Cannot connect to device ${device.address}: Permissions missing.")
            return
        }
        if (_connectedGattClientDevices.value.containsKey(device.address)) {
            Log.d(TAG, "GATT Client: Already connected or connecting to ${device.address}")
            return
        }
        Log.i(TAG, "GATT Client: Attempting to connect to GATT server on device: ${device.address}")
        try {
            val gatt = device.connectGatt(this, false, gattClientCallback, BluetoothDevice.TRANSPORT_LE)
            if (gatt == null) {
                Log.e(TAG, "GATT Client: device.connectGatt returned null for ${device.address}. Connection failed.")
            } else {
                 // Store it temporarily, actual connection confirmed in callback
                _connectedGattClientDevices.update { it + (device.address to gatt) } // Optimistic update, or wait for callback
            }
        } catch (se: SecurityException) {
            Log.e(TAG, "GATT Client: SecurityException on connectGatt for ${device.address}: ${se.message}", se)
        }
    }

    @Synchronized
    fun disconnectFromDevice(deviceAddress: String) {
         if (!checkBlePermissions()) {
            Log.e(TAG, "GATT Client: Cannot disconnect from device $deviceAddress: Permissions missing.")
            return
        }
        _connectedGattClientDevices.value[deviceAddress]?.let { gatt ->
            Log.i(TAG, "GATT Client: Requesting disconnect from $deviceAddress")
            try {
                gatt.disconnect()
            } catch (se: SecurityException) {
                 Log.e(TAG, "GATT Client: SecurityException on disconnect for $deviceAddress: ${se.message}", se)
                 // Manually clean up if disconnect throws
                gatt.close()
                _connectedGattClientDevices.update { it - deviceAddress }
            }
        } ?: Log.w(TAG, "GATT Client: Cannot disconnect, no active GATT client for $deviceAddress")
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val deviceAddress = gatt.device.address
            Log.d(TAG, "GATT Client: onConnectionStateChange for $deviceAddress, Status: $status, NewState: $newState")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    Log.i(TAG, "GATT Client: Successfully CONNECTED to $deviceAddress")
                    _connectedGattClientDevices.update { currentMap ->
                        // Ensure we are updating the map with the correct gatt instance if it was already there due to optimistic update
                        if (currentMap.containsKey(deviceAddress)) currentMap else currentMap + (deviceAddress to gatt)
                    }
                    serviceScope.launch { // Use serviceScope for coroutine
                        delay(600) // Delay recommended before service discovery by some Android docs/blogs
                        Log.d(TAG, "GATT Client: Discovering services for $deviceAddress...")
                        try { gatt.discoverServices() } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc on discoverServices for $deviceAddress", se)}
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    Log.i(TAG, "GATT Client: Successfully DISCONNECTED from $deviceAddress")
                    try { gatt.close() } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc on gatt.close for $deviceAddress", se) }
                    _connectedGattClientDevices.update { it - deviceAddress }
                }
            } else { // Error status
                Log.e(TAG, "GATT Client: Connection state error for $deviceAddress. Status: $status, NewState: $newState. Closing GATT.")
                try { gatt.close() } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc on gatt.close after error for $deviceAddress", se) }
                _connectedGattClientDevices.update { it - deviceAddress }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val deviceAddress = gatt.device.address
            Log.d(TAG, "GATT Client: onServicesDiscovered for $deviceAddress, Status: $status")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Client: Services discovered successfully for $deviceAddress.")
                gatt.getService(BITCHAT_SERVICE_UUID)?.let { service ->
                    Log.d(TAG, "GATT Client: BitChat Service ${service.uuid.toString().takeLast(12)} found on $deviceAddress.")
                    service.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)?.let { char ->
                        Log.d(TAG, "GATT Client: BitChat Char ${char.uuid.toString().takeLast(12)} found on $deviceAddress. Properties: ${char.properties}")
                        enableNotificationsOnCharacteristic(gatt, char)
                    } ?: Log.w(TAG, "GATT Client: BitChat characteristic NOT FOUND on $deviceAddress")
                } ?: Log.w(TAG, "GATT Client: BitChat service NOT FOUND on $deviceAddress")
            } else {
                Log.w(TAG, "GATT Client: Service discovery FAILED for $deviceAddress with status: $status")
            }
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            val deviceAddress = gatt.device.address
            Log.d(TAG, "GATT Client: onCharacteristicRead for Char ${characteristic.uuid.toString().takeLast(12)} from $deviceAddress, Status: $status, Size: ${value.size} bytes")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (characteristic.uuid == BITCHAT_CHARACTERISTIC_UUID) {
                    Log.i(TAG, "GATT Client: Data read from BitChat Char on $deviceAddress: ${value.size} bytes.")
                    handleReceivedRawData(value, gatt.device)
                }
            } else {
                Log.w(TAG, "GATT Client: Characteristic read FAILED for ${characteristic.uuid} from $deviceAddress, Status: $status")
            }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
             val deviceAddress = gatt.device.address
            Log.d(TAG, "GATT Client: onCharacteristicWrite for Char ${characteristic.uuid.toString().takeLast(12)} to $deviceAddress, Status: $status")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Client: Data written successfully to BitChat Char on $deviceAddress.")
            } else {
                Log.w(TAG, "GATT Client: Characteristic write FAILED for ${characteristic.uuid} to $deviceAddress, Status: $status")
                // TODO: Notify sender (e.g. ViewModel via MessageMetadataService) about write failure
            }
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            // This is for notifications/indications
            val deviceAddress = gatt.device.address
            Log.d(TAG, "GATT Client: onCharacteristicChanged for Char ${characteristic.uuid.toString().takeLast(12)} from $deviceAddress, Size: ${value.size} bytes")
             if (characteristic.uuid == BITCHAT_CHARACTERISTIC_UUID) {
                Log.i(TAG, "GATT Client: Notification data received from BitChat Char on $deviceAddress: ${value.size} bytes.")
                handleReceivedRawData(value, gatt.device)
            }
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            val deviceAddress = gatt.device.address
            Log.d(TAG, "GATT Client: onDescriptorWrite for Desc ${descriptor.uuid.toString().takeLast(12)} on $deviceAddress, Status: $status")
            if (descriptor.uuid == CLIENT_CHARACTERISTIC_CONFIG_UUID && descriptor.characteristic.uuid == BITCHAT_CHARACTERISTIC_UUID) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    if (Arrays.equals(descriptor.value, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
                        Log.i(TAG, "GATT Client: Successfully ENABLED notifications for BitChat Char on $deviceAddress.")
                    } else if (Arrays.equals(descriptor.value, BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)) {
                        Log.i(TAG, "GATT Client: Successfully DISABLED notifications for BitChat Char on $deviceAddress.")
                    }
                } else {
                     Log.w(TAG, "GATT Client: FAILED to write CCCD for BitChat Char on $deviceAddress, Status: $status")
                }
            }
        }
    }

    // --- Data Handling ---
    private fun handleReceivedRawData(rawData: ByteArray, fromDevice: BluetoothDevice) {
        Log.i(TAG, "Handling ${rawData.size} raw bytes received from ${fromDevice.address}")
        // TODO: Reassembly logic if data is fragmented across multiple BLE packets.
        // For now, assume one BitchatPacket per BLE characteristic write/notification.

        // TODO: Need EncryptionService instance for deserialization if messages are encrypted.
        // For now, assuming public messages or placeholder EncryptionService.
        val encryptionService = EncryptionService() // Placeholder, inject properly
        val packet = BinaryProtocol.deserializePacket(rawData, encryptionService)

        if (packet != null) {
            Log.i(TAG, "Successfully deserialized BitchatPacket ID ${packet.id} from ${packet.sourceId} (Device: ${fromDevice.address})")
            // TODO: Additional validation (e.g., sourceId matches fromDevice, if applicable)
            serviceScope.launch {
                _processedReceivedPacketsFlow.emit(packet)
                Log.d(TAG, "Emitted packet ${packet.id} to processedReceivedPacketsFlow.")
            }
        } else {
            Log.w(TAG, "Failed to deserialize BitchatPacket from ${fromDevice.address}. Raw data (hex): ${rawData.joinToString("") { "%02x".format(it) }}")
        }
    }

    /**
     * Sends a pre-serialized BitchatPacket to connected peers.
     * This now takes the BitchatPacket object as well for metadata/tracking.
     */
    fun sendDataToPeers(serializedPacket: ByteArray, originalPacket: BitchatPacket) {
        if (!checkBlePermissions()) {
            Log.e(TAG, "Cannot send data: Permissions missing.")
            return
        }
        if (serializedPacket.isEmpty()) {
            Log.w(TAG, "Attempted to send empty data for packet ${originalPacket.id}.")
            return
        }

        Log.i(TAG, "Attempting to send packet ${originalPacket.id} (${serializedPacket.size} bytes) to peers.")

        // Option 1: Send to all devices connected to our GATT Server that are subscribed
        val serverTargets = _connectedGattServerDevices.value.values.filter { subscribedDevices.contains(it) }
        serverTargets.forEach { device ->
            gattServer?.getService(BITCHAT_SERVICE_UUID)?.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)?.let { char ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    try {
                        val statusCode = gattServer?.notifyCharacteristicChanged(device, char, false, serializedPacket)
                        Log.d(TAG, "GATT Server: notifyCharacteristicChanged for ${device.address}, packet ${originalPacket.id}, status: $statusCode (0 is success)")
                        if(statusCode != BluetoothStatusCodes.SUCCESS) Log.w(TAG, "Notify failed for ${device.address} with status code: $statusCode")
                    } catch (se: SecurityException) { Log.e(TAG, "GATT Server: SecurityExc notifyCharacteristicChanged for ${device.address}", se)}
                } else {
                    char.value = serializedPacket
                    try {
                        val success = gattServer?.notifyCharacteristicChanged(device, char, false)
                        Log.d(TAG, "GATT Server: notifyCharacteristicChanged for ${device.address}, packet ${originalPacket.id}, success: $success")
                    } catch (se: SecurityException) { Log.e(TAG, "GATT Server: SecurityExc notifyCharacteristicChanged for ${device.address}", se)}
                }
            } ?: Log.w(TAG, "GATT Server: BitChat characteristic not found for sending notification to ${device.address}")
        }
        if (serverTargets.isNotEmpty()) Log.i(TAG, "Sent packet ${originalPacket.id} as notification to ${serverTargets.size} subscribed GATT server clients.")


        // Option 2: Send to all devices we are connected to as a GATT Client
        _connectedGattClientDevices.value.values.forEach { gatt ->
            gatt.getService(BITCHAT_SERVICE_UUID)?.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)?.let { char ->
                val writeType = if ((char.properties and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE) != 0) {
                    BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                } else {
                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                }

                serviceScope.launch { // Perform GATT writes on a coroutine
                    Log.d(TAG, "GATT Client: Writing ${serializedPacket.size} bytes (packet ${originalPacket.id}) to ${gatt.device.address}, type: $writeType")
                    val success = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        try { gatt.writeCharacteristic(char, serializedPacket, writeType) == BluetoothStatusCodes.SUCCESS } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc writing to ${gatt.device.address}", se); false }
                    } else {
                        char.value = serializedPacket
                        char.writeType = writeType
                        try { gatt.writeCharacteristic(char) } catch (se: SecurityException) { Log.e(TAG, "GATT Client: SecurityExc writing to ${gatt.device.address}", se); false }
                    }
                    if (success) {
                        Log.i(TAG, "GATT Client: Successfully initiated write of packet ${originalPacket.id} to ${gatt.device.address}")
                    } else {
                        Log.w(TAG, "GATT Client: Failed to initiate write of packet ${originalPacket.id} to ${gatt.device.address}")
                    }
                }
            } ?: Log.w(TAG, "GATT Client: BitChat characteristic not found for writing to ${gatt.device.address}")
        }
         if (_connectedGattClientDevices.value.isNotEmpty()) Log.i(TAG, "Attempted to send packet ${originalPacket.id} as characteristic write to ${_connectedGattClientDevices.value.size} GATT client connections.")

        if (serverTargets.isEmpty() && _connectedGattClientDevices.value.isEmpty()) {
            Log.w(TAG, "No connected peers to send packet ${originalPacket.id} to.")
        }
    }

    private fun enableNotificationsOnCharacteristic(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
        if (!checkBlePermissions()) {
            Log.e(TAG, "GATT Client: Cannot enable notifications for ${characteristic.uuid} on ${gatt.device.address}: Permissions missing.")
            return
        }
        if ((characteristic.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) == 0) {
            Log.w(TAG, "GATT Client: Characteristic ${characteristic.uuid} on ${gatt.device.address} does not support NOTIFY.")
            return
        }

        val cccd = characteristic.getDescriptor(CLIENT_CHARACTERISTIC_CONFIG_UUID)
        if (cccd == null) {
            Log.w(TAG, "GATT Client: CCCD not found for characteristic ${characteristic.uuid} on ${gatt.device.address}")
            return
        }

        Log.d(TAG, "GATT Client: Enabling notifications for ${characteristic.uuid} on ${gatt.device.address}")
        try {
            gatt.setCharacteristicNotification(characteristic, true) // Enable locally first

            val writeSuccess : Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS
            } else {
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(cccd)
            }
            if (writeSuccess) {
                Log.i(TAG, "GATT Client: Notification enabling procedure initiated for ${characteristic.uuid} on ${gatt.device.address}.")
            } else {
                Log.w(TAG, "GATT Client: Failed to initiate CCCD write for notification enabling on ${gatt.device.address}.")
                gatt.setCharacteristicNotification(characteristic, false) // Revert local enable if write fails
            }
        } catch (se: SecurityException) {
            Log.e(TAG, "GATT Client: SecurityException enabling notifications for ${gatt.device.address}: ${se.message}", se)
            try { gatt.setCharacteristicNotification(characteristic, false) } catch (e: Exception) {} // Best effort to revert
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "Service onDestroy. Stopping BLE operations and cancelling scope.")
        serviceScope.cancel()
        stopAdvertising()
        stopScanning()
        stopGattServer() // Also clears _connectedGattServerDevices and subscribedDevices

        // Close all client GATT connections
        _connectedGattClientDevices.value.values.forEach { gatt ->
            try {
                if (checkBlePermissions()) gatt.close()
            } catch (se: SecurityException) {
                Log.e(TAG, "SecurityException closing client GATT on destroy for ${gatt.device.address}", se)
            } catch (e: Exception) {
                 Log.e(TAG, "Exception closing client GATT on destroy for ${gatt.device.address}", e)
            }
        }
        _connectedGattClientDevices.value = emptyMap()

        try {
            stopForeground(true)
        } catch (e: Exception) {
            Log.e(TAG, "Exception stopping foreground service: ${e.message}", e)
        }
        Log.i(TAG, "Service destroyed.")
    }
}
