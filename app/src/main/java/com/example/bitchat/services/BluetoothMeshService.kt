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
import android.util.Log // Standard Android logging
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import com.example.bitchat.MainActivity // Assuming MainActivity is in this package
import com.example.bitchat.R // Assuming R is generated in this package
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.*

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
    val isScanning: StateFlow<Boolean> = _isScanning

    private val _isAdvertising = MutableStateFlow(false)
    val isAdvertising: StateFlow<Boolean> = _isAdvertising

    private val _connectedDevices = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val connectedDevices: StateFlow<List<BluetoothDevice>> = _connectedDevices

    // TODO: Add flows for received messages, peer discovery, errors, etc.

    companion object {
        private const val TAG = "BluetoothMeshService"
        private const val NOTIFICATION_CHANNEL_ID = "BitChatServiceChannel"
        private const val NOTIFICATION_ID = 101

        // These UUIDs MUST match the iOS application's UUIDs
        val BITCHAT_SERVICE_UUID: UUID = UUID.fromString("00001234-0000-1000-8000-00805F9B34FB") // Replace with actual
        val BITCHAT_CHARACTERISTIC_UUID: UUID = UUID.fromString("00001235-0000-1000-8000-00805F9B34FB") // Replace with actual
        // Add other characteristic UUIDs if needed (e.g., for control points, large data transfer)
    }

    inner class LocalBinder : Binder() {
        fun getService(): BluetoothMeshService = this@BluetoothMeshService
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Service onCreate")
        bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth not supported on this device.")
            // TODO: Notify UI or handle this case appropriately
            stopSelf() // Stop the service if Bluetooth is not supported
            return
        }

        bluetoothLeScanner = bluetoothAdapter?.bluetoothLeScanner
        bluetoothLeAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "Service onStartCommand")
        startForeground(NOTIFICATION_ID, createNotification())

        // TODO: Initialize scanning, advertising, GATT server based on intent or stored state
        // For now, let's try to start advertising and GATT server if permissions are granted
        if (checkPermissions()) {
            startGattServer()
            startAdvertising()
            startScanning() // Start scanning as well
        } else {
            Log.w(TAG, "Bluetooth permissions not granted. Cannot start BLE operations.")
            // TODO: Request permissions from UI or handle appropriately
        }

        return START_STICKY // Keep service running
    }

    private fun checkPermissions(): Boolean {
        val requiredPermissions = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            requiredPermissions.add(Manifest.permission.BLUETOOTH_SCAN)
            requiredPermissions.add(Manifest.permission.BLUETOOTH_CONNECT)
            requiredPermissions.add(Manifest.permission.BLUETOOTH_ADVERTISE)
        } else {
            requiredPermissions.add(Manifest.permission.BLUETOOTH)
            requiredPermissions.add(Manifest.permission.BLUETOOTH_ADMIN)
        }
        // Location permission is required for BLE scanning before Android S,
        // and for `neverForLocation` flag on BLUETOOTH_SCAN on Android S+ to work reliably on some devices.
        requiredPermissions.add(Manifest.permission.ACCESS_FINE_LOCATION)

        return requiredPermissions.all {
            ActivityCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "BitChat Background Service",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(serviceChannel)
        }
    }

    private fun createNotification(): Notification {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("BitChat Active")
            .setContentText("Running Bluetooth Mesh service...")
            .setSmallIcon(R.mipmap.ic_launcher) // Replace with actual app icon
            .setContentIntent(pendingIntent)
            .build()
    }

    // --- Advertising ---
    fun startAdvertising() {
        if (!checkPermissions() || bluetoothLeAdvertiser == null) {
            Log.e(TAG, "Cannot start advertising: Permissions not granted or advertiser not available.")
            _isAdvertising.value = false
            return
        }
        if (_isAdvertising.value) {
            Log.d(TAG, "Already advertising.")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY) // Or balanced/low_power
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true) // Important for GATT server
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false) // Depending on privacy requirements
            .addServiceUuid(ParcelUuid(BITCHAT_SERVICE_UUID))
            .build()

        // Scan Response data can be added if needed
        // val scanResponseData = AdvertiseData.Builder().setIncludeDeviceName(true).build()

        try {
            bluetoothLeAdvertiser?.startAdvertising(settings, data, advertiseCallback)
            _isAdvertising.value = true
            Log.d(TAG, "Started Advertising with Service UUID: $BITCHAT_SERVICE_UUID")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException while starting advertising: ${e.message}")
            _isAdvertising.value = false
        }
    }

    fun stopAdvertising() {
        if (!checkPermissions() || bluetoothLeAdvertiser == null) {
            Log.e(TAG, "Cannot stop advertising: Permissions not granted or advertiser not available.")
            return
        }
        if (!_isAdvertising.value) {
            Log.d(TAG, "Not currently advertising.")
            return
        }
        try {
            bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
            _isAdvertising.value = false
            Log.d(TAG, "Stopped Advertising")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException while stopping advertising: ${e.message}")
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            Log.i(TAG, "LE Advertise Started.")
            _isAdvertising.value = true
        }

        override fun onStartFailure(errorCode: Int) {
            Log.w(TAG, "LE Advertise Failed: $errorCode")
            _isAdvertising.value = false
            // TODO: Handle specific error codes (e.g., ADVERTISE_FAILED_DATA_TOO_LARGE)
        }
    }

    // --- Scanning ---
    fun startScanning() {
        if (!checkPermissions() || bluetoothLeScanner == null) {
            Log.e(TAG, "Cannot start scanning: Permissions not granted or scanner not available.")
            _isScanning.value = false
            return
        }
        if (_isScanning.value) {
            Log.d(TAG, "Already scanning.")
            return
        }

        val scanFilters: List<ScanFilter> = listOf(
            ScanFilter.Builder().setServiceUuid(ParcelUuid(BITCHAT_SERVICE_UUID)).build()
        )
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY) // Or balanced/low_power
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
            .setNumOfMatches(ScanSettings.MATCH_NUM_ONE_ADVERTISEMENT) // Or few/max, adjust as needed
            .setReportDelay(0L) // Report results immediately
            .build()

        try {
            bluetoothLeScanner?.startScan(scanFilters, scanSettings, scanCallback)
            _isScanning.value = true
            Log.d(TAG, "Started Scanning for Service UUID: $BITCHAT_SERVICE_UUID")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException while starting scan: ${e.message}")
            _isScanning.value = false
        }
    }

    fun stopScanning() {
        if (!checkPermissions() || bluetoothLeScanner == null) {
            Log.e(TAG, "Cannot stop scanning: Permissions not granted or scanner not available.")
            return
        }
         if (!_isScanning.value) {
            Log.d(TAG, "Not currently scanning.")
            return
        }
        try {
            bluetoothLeScanner?.stopScan(scanCallback)
            _isScanning.value = false
            Log.d(TAG, "Stopped Scanning")
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException while stopping scan: ${e.message}")
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            super.onScanResult(callbackType, result)
            val device = result.device
            Log.i(TAG, "Scan Result: ${device.address} - Name: ${device.name ?: "N/A"}, RSSI: ${result.rssi}")
            // TODO: Process scan result - e.g., add to a list of discovered peers, attempt connection
            // For now, just log it. Later, we'll connect to it.
            // Example: if suitable conditions met: connectToDevice(device)
        }

        override fun onBatchScanResults(results: List<ScanResult>) {
            super.onBatchScanResults(results)
            Log.i(TAG, "Batch Scan Results: ${results.size} devices found")
            results.forEach { result ->
                 val deviceName = if (ActivityCompat.checkSelfPermission(this@BluetoothMeshService, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                    result.device.name ?: "N/A" // Attempt to get name if permission allows
                } else {
                    "N/A (No Connect Perm)" // Indicate permission issue if name cannot be retrieved
                }
                Log.i(TAG, "  Device: Addr=${result.device.address}, Name=$deviceName, RSSI=${result.rssi}")
            }
            // TODO: Process batch results similarly to individual onScanResult. This involves:
            //  - Adding new/updated peer info to a central peer manager/list.
            //  - Potentially triggering connection attempts based on strategy.
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "Scan Failed: Error Code: $errorCode")
            _isScanning.value = false
            // TODO: Handle specific error codes (e.g., SCAN_FAILED_APPLICATION_REGISTRATION_FAILED)
        }
    }

    // --- GATT Server ---
    private fun startGattServer() {
        if (!checkPermissions()) {
            Log.e(TAG, "Cannot start GATT server: Permissions not granted.")
            return
        }
        gattServer = bluetoothManager.openGattServer(this, gattServerCallback)
        if (gattServer == null) {
            Log.e(TAG, "Unable to create GATT server.")
            return
        }

        val service = BluetoothGattService(BITCHAT_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val characteristic = BluetoothGattCharacteristic(
            BITCHAT_CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        // Add a CCCD (Client Characteristic Configuration Descriptor) for NOTIFY
        val cccd = BluetoothGattDescriptor(
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"), // Standard CCCD UUID
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        characteristic.addDescriptor(cccd)
        service.addCharacteristic(characteristic)

        // Add other characteristics if needed

        gattServer?.addService(service)
        Log.d(TAG, "GATT Server started and service added.")
    }

    private fun stopGattServer() {
        if (!checkPermissions()) {
            Log.e(TAG, "Cannot stop GATT server: Permissions not granted.")
            return
        }
        gattServer?.close()
        gattServer = null
        Log.d(TAG, "GATT Server stopped.")
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            super.onConnectionStateChange(device, status, newState)
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "GATT Server: Device Connected - ${device.address}")
                _connectedDevices.value = _connectedDevices.value + device
                // TODO: Handle new connection (e.g., start service discovery on client side if this device is also a client)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.i(TAG, "GATT Server: Device Disconnected - ${device.address}")
                 _connectedDevices.value = _connectedDevices.value - device
                // TODO: Handle disconnection
            }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic)
            Log.d(TAG, "GATT Server: Read request for characteristic ${characteristic.uuid} from ${device.address}")
            if (BITCHAT_CHARACTERISTIC_UUID == characteristic.uuid) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, /* TODO: data to send */ "Hello".toByteArray())
            } else {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
            }
        }

        override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)
            val strValue = value?.toString(Charsets.UTF_8) ?: "null"
            Log.d(TAG, "GATT Server: Write request for characteristic ${characteristic.uuid} from ${device.address}, value: $strValue")
            if (BITCHAT_CHARACTERISTIC_UUID == characteristic.uuid) {
                // TODO: Process received data (value)
                // This is where incoming messages from peers will be handled.
                // It will involve parsing BitchatPacket, decryption, etc.
                // For now, just log it.
                Log.i(TAG, "Received data on BITCHAT_CHARACTERISTIC: $strValue")

                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                }
                // TODO: If the characteristic supports NOTIFY, and this write is from a client enabling notifications, store this.
                // Or, if it's data, potentially notify other connected clients or process the message.
            } else {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                }
            }
        }

        override fun onDescriptorWriteRequest(device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            super.onDescriptorWriteRequest(device, requestId, descriptor, preparedWrite, responseNeeded, offset, value)
            if (descriptor.uuid == UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")) { // CCCD
                if (Arrays.equals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, value)) {
                    Log.i(TAG, "GATT Server: Notifications enabled for ${descriptor.characteristic.uuid} by ${device.address}")
                    // TODO: Store that this device wants notifications for this characteristic
                } else if (Arrays.equals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE, value)) {
                    Log.i(TAG, "GATT Server: Notifications disabled for ${descriptor.characteristic.uuid} by ${device.address}")
                    // TODO: Store that this device no longer wants notifications
                }
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                }
            } else {
                 if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                }
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            super.onServiceAdded(status, service)
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Service ${service?.uuid} added successfully.")
            } else {
                Log.w(TAG, "GATT Service addition failed with status: $status")
            }
        }
        // TODO: Implement other GATT server callbacks as needed (onDescriptorReadRequest, onExecuteWrite, onNotificationSent, etc.)
    }

    // --- GATT Client (placeholder for now) ---
    private val connectedGattClients = mutableMapOf<String, BluetoothGatt>()

    fun connectToDevice(device: BluetoothDevice) {
        if (!checkPermissions()) {
            Log.e(TAG, "Cannot connect to device: Permissions not granted.")
            return
        }
        if (connectedGattClients.containsKey(device.address)) {
            Log.d(TAG, "Already connected or connecting to ${device.address}")
            return
        }
        Log.i(TAG, "Attempting to connect to GATT server on device: ${device.address}")
        // Auto-connect true can be problematic, false is usually preferred for explicit control
        val gattClient = device.connectGatt(this, false, gattClientCallback, BluetoothDevice.TRANSPORT_LE)
        connectedGattClients[device.address] = gattClient
    }

    fun disconnectFromDevice(deviceAddress: String) {
         if (!checkPermissions()) {
            Log.e(TAG, "Cannot disconnect from device: Permissions not granted.")
            return
        }
        connectedGattClients[deviceAddress]?.disconnect()
        // close() will be called in onConnectionStateChange when disconnected
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val deviceAddress = gatt.device.address
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    Log.i(TAG, "GATT Client: Connected to $deviceAddress")
                     _connectedDevices.value = _connectedDevices.value.toMutableList().apply {
                        if (!this.any { it.address == gatt.device.address }) add(gatt.device)
                    }.toList()
                    // Discover services after successful connection
                    gatt.discoverServices()
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    Log.i(TAG, "GATT Client: Disconnected from $deviceAddress")
                    _connectedDevices.value = _connectedDevices.value.filterNot { it.address == gatt.device.address }
                    gatt.close()
                    connectedGattClients.remove(deviceAddress)
                }
            } else {
                Log.w(TAG, "GATT Client: Connection state change error for $deviceAddress, status: $status, newState: $newState")
                _connectedDevices.value = _connectedDevices.value.filterNot { it.address == gatt.device.address }
                gatt.close()
                connectedGattClients.remove(deviceAddress)
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Client: Services discovered for ${gatt.device.address}")
                val service = gatt.getService(BITCHAT_SERVICE_UUID)
                if (service == null) {
                    Log.w(TAG, "GATT Client: BitChat service not found on ${gatt.device.address}")
                    // TODO: Handle service not found
                    return
                }
                val characteristic = service.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)
                if (characteristic == null) {
                    Log.w(TAG, "GATT Client: BitChat characteristic not found on ${gatt.device.address}")
                    // TODO: Handle characteristic not found
                    return
                }
                // TODO: Enable notifications if needed, read initial data, etc.
                // Example: enableNotifications(gatt, characteristic)
            } else {
                Log.w(TAG, "GATT Client: Service discovery failed for ${gatt.device.address} with status: $status")
            }
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            // In Android 13+ (API 33+), this callback is `onCharacteristicRead(gatt, characteristic, value, status)`.
            // For older versions, it's `onCharacteristicRead(gatt, characteristic, status)` and you get value from characteristic.value.
            // This template uses the newer signature, ensure your minSdk and compileSdk are appropriate or handle legacy.
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Client: Characteristic ${characteristic.uuid} read from ${gatt.device.address}: ${value.toString(Charsets.UTF_8)}")
                // TODO: Process read data
            } else {
                Log.w(TAG, "GATT Client: Characteristic read failed for ${characteristic.uuid} from ${gatt.device.address}, status: $status")
            }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            super.onCharacteristicWrite(gatt, characteristic, status)
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT Client: Characteristic ${characteristic.uuid} written to ${gatt.device.address}")
            } else {
                Log.w(TAG, "GATT Client: Characteristic write failed for ${characteristic.uuid} from ${gatt.device.address}, status: $status")
            }
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            // Similar to onCharacteristicRead, signature changed in API 33.
            // This template uses the newer signature.
            val strValue = value.toString(Charsets.UTF_8)
            Log.i(TAG, "GATT Client: Characteristic ${characteristic.uuid} changed on ${gatt.device.address}: $strValue")
            // TODO: Process incoming notification data (this is where messages from peers arrive if notifications are enabled)
        }
        // TODO: Implement other GATT client callbacks as needed
    }

    // --- Public methods for interaction (called from ViewModel or other components) ---
    fun sendMessage(deviceAddress: String, message: String) {
        if (!checkPermissions()) {
            Log.e(TAG, "Cannot send message: Permissions not granted.")
            return
        }
        val gatt = connectedGattClients[deviceAddress]
        if (gatt == null) {
            Log.w(TAG, "Cannot send message: Not connected to device $deviceAddress")
            return
        }
        val service = gatt.getService(BITCHAT_SERVICE_UUID)
        if (service == null) {
            Log.w(TAG, "Cannot send message: BitChat service not found on $deviceAddress")
            return
        }
        val characteristic = service.getCharacteristic(BITCHAT_CHARACTERISTIC_UUID)
        if (characteristic == null) {
            Log.w(TAG, "Cannot send message: BitChat characteristic not found on $deviceAddress")
            return
        }

        val writeType = if ((characteristic.properties and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE) != 0) {
            BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        } else if ((characteristic.properties and BluetoothGattCharacteristic.PROPERTY_WRITE) != 0) {
            BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        } else {
            Log.e(TAG, "Characteristic ${characteristic.uuid} does not support write operations.")
            return
        }

        serviceScope.launch {
            val success : Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                 gatt.writeCharacteristic(characteristic, message.toByteArray(Charsets.UTF_8), writeType) == BluetoothStatusCodes.SUCCESS
            } else {
                characteristic.value = message.toByteArray(Charsets.UTF_8)
                characteristic.writeType = writeType
                gatt.writeCharacteristic(characteristic)
            }
            if (success) {
                Log.i(TAG, "Message sent to $deviceAddress: $message")
            } else {
                Log.w(TAG, "Failed to initiate message send to $deviceAddress")
            }
        }
    }

    // Function to enable notifications on a characteristic (GATT Client role)
    fun enableNotifications(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
        if (!checkPermissions()) return

        val cccd = characteristic.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"))
        if (cccd == null) {
            Log.w(TAG, "CCCD not found for characteristic ${characteristic.uuid}")
            return
        }

        val enableNotificationValue = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE

        val success : Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeDescriptor(cccd, enableNotificationValue) == BluetoothStatusCodes.SUCCESS
        } else {
            cccd.value = enableNotificationValue
            gatt.writeDescriptor(cccd)
        }

        if (success) {
            gatt.setCharacteristicNotification(characteristic, true)
            Log.i(TAG, "Notification enabling initiated for ${characteristic.uuid}")
        } else {
            Log.w(TAG, "Failed to initiate notification enabling for ${characteristic.uuid}")
        }
    }


    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "Service onDestroy")
        serviceScope.cancel() // Cancel all coroutines
        stopAdvertising()
        stopScanning()
        stopGattServer()
        connectedGattClients.values.forEach { if(checkPermissions()) it.close() }
        connectedGattClients.clear()
        stopForeground(true)
    }
}
