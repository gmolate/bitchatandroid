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

/**
 * Contiene información sobre el estado de conectividad de un peer.
 * @param deviceAddress Dirección MAC del dispositivo, usada como clave única.
 * @param bluetoothDevice El objeto BluetoothDevice más reciente, puede ser nulo si solo se conoce la dirección.
 * @param connectionState El estado actual de la conexión (ej. IDLE, CONNECTED, ERROR).
 * @param lastSeenTimestamp Marca de tiempo de la última vez que se vio o interactuó con el peer.
 * @param reconnectionAttempts Contador de intentos de reconexión.
 * @param gatt El objeto BluetoothGatt para esta conexión de cliente, si existe.
 * @param isKnownGoodPeer Verdadero si hemos tenido una conexión exitosa previamente.
 * @param wantsNotifications Verdadero si este peer se ha suscrito a nuestras notificaciones (rol de servidor GATT).
 */
data class PeerConnectivityInfo(
    val deviceAddress: String,
    var bluetoothDevice: BluetoothDevice?,
    var connectionState: BleOperationState,
    var lastSeenTimestamp: Long = System.currentTimeMillis(),
    var reconnectionAttempts: Int = 0,
    var gatt: BluetoothGatt? = null,
    var isKnownGoodPeer: Boolean = false,
    var wantsNotifications: Boolean = false
)

/**
 * Representa los diferentes estados operativos del servicio BLE.
 * Es un 'sealed class' para poder asociar datos a ciertos estados.
 */
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
            IDLE -> "Inactivo"
            SCANNING -> "Buscando peers"
            ADVERTISING -> "Anunciando"
            is CONNECTING_TO_PEER -> "Conectando a ${peerAddress.takeLast(6)}"
            is RECONNECTING_TO_PEER -> "Reconectando a ${peerAddress.takeLast(6)} (Intento ${attempt})"
            is CONNECTED_AS_CLIENT -> "Conectado a ${deviceName ?: peerAddress.takeLast(6)}"
            is CONNECTED_AS_SERVER -> "Peer conectado: ${deviceName ?: peerAddress.takeLast(6)}"
            ERROR_PERMISSIONS -> "Error: Faltan permisos"
            ERROR_BLUETOOTH_OFF -> "Error: Bluetooth apagado"
            is ERROR_CONNECTION_FAILED -> "Error: Conexión con ${peerAddress?.takeLast(6) ?: "desconocido"} ${if(isTimeout) "expiró" else "falló (código $errorCode)"}"
            ERROR_GENERIC -> "Error: Fallo en operación BLE"
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

    private val _processedReceivedPacketsFlow = MutableSharedFlow<BitchatPacket>(replay = 0, extraBufferCapacity = 128, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    val processedReceivedPacketsFlow: SharedFlow<BitchatPacket> = _processedReceivedPacketsFlow.asSharedFlow()

    // --- Gestión de Peers ---
    private val knownPeers = ConcurrentHashMap<String, PeerConnectivityInfo>()
    private val _knownPeersStateFlow = MutableStateFlow<Map<String, PeerConnectivityInfo>>(emptyMap())
    /** Expone el estado de los peers conocidos, incluyendo su estado de conectividad. */
    val knownPeersStateFlow: StateFlow<Map<String, PeerConnectivityInfo>> = _knownPeersStateFlow.asStateFlow()

    private val gattClientConnections = ConcurrentHashMap<String, BluetoothGatt>()
    private val gattServerConnections = ConcurrentHashMap<String, BluetoothDevice>()
    private val subscribedDevices = Collections.synchronizedSet(HashSet<BluetoothDevice>())
    private val activeGattContinuations = ConcurrentHashMap<String, CancellableContinuation<BluetoothGatt?>>()

    companion object {
        private const val TAG = "BTMeshService"
        // ... (otras constantes como UUIDs, timeouts, etc.)
        const val CONNECTION_TIMEOUT_MS = 30_000L
        const val INITIAL_RECONNECTION_DELAY_MS = 5_000L
        const val MAX_RECONNECTION_ATTEMPTS = 5
        const val MAX_RECONNECTION_DELAY_MS = 60_000L
        val BITCHAT_SERVICE_UUID: UUID = UUID.fromString("0000b17c-0000-1000-8000-00805f9b34fb")
        val BITCHAT_CHARACTERISTIC_UUID: UUID = UUID.fromString("0000b17d-0000-1000-8000-00805f9b34fb")
        val CLIENT_CHARACTERISTIC_CONFIG_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    inner class LocalBinder : Binder() {
        fun getService(): BluetoothMeshService = this@BluetoothMeshService
    }

    override fun onBind(intent: Intent): IBinder = binder.also { Log.d(TAG, "Servicio enlazado (onBind).") }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Servicio onCreate. Instancia: ${this.hashCode()}")
        bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth no soportado. Deteniendo servicio.")
            _bleOperationState.value = BleOperationState.ERROR_GENERIC
            stopSelf()
            return
        }
        if (!bluetoothAdapter!!.isEnabled) {
            Log.w(TAG, "Bluetooth está APAGADO. Las operaciones fallarán hasta que se encienda.")
            _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF
        }

        bluetoothLeScanner = bluetoothAdapter?.bluetoothLeScanner
        bluetoothLeAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        createNotificationChannel()
        Log.i(TAG, "Servicio creado exitosamente.")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "Servicio onStartCommand. Acción: ${intent?.action}, Flags: $flags, StartId: $startId")
        startForeground(101, createNotification()) // NOTIFICATION_ID = 101
        if (checkBlePermissions()) {
            if (bluetoothAdapter?.isEnabled == true) {
                Log.i(TAG, "Permisos OK y Bluetooth ENCENDIDO. Inicializando operaciones BLE.")
                initializeBleOperations()
            } else {
                Log.w(TAG, "Permisos OK, pero Bluetooth está APAGADO. Esperando a que se encienda.")
                _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF
            }
        } else {
            Log.w(TAG, "Permisos BLE NO concedidos. No se pueden iniciar operaciones BLE.")
            _bleOperationState.value = BleOperationState.ERROR_PERMISSIONS
        }
        return START_STICKY
    }

    fun initializeBleOperations() {
        if (bluetoothAdapter?.isEnabled != true) {
            Log.w(TAG, "No se puede inicializar BLE: Bluetooth está apagado.")
            _bleOperationState.value = BleOperationState.ERROR_BLUETOOTH_OFF
            return
        }
        if (!checkBlePermissions()) {
            Log.w(TAG, "No se puede inicializar BLE: Faltan permisos.")
            _bleOperationState.value = BleOperationState.ERROR_PERMISSIONS
            return
        }
        Log.i(TAG, "Inicializando operaciones BLE: Servidor GATT, Anuncio y Escaneo.")
        _bleOperationState.value = BleOperationState.IDLE
        serviceScope.launch {
            startGattServer()
            startAdvertising()
            startScanning()
        }
    }

    private fun checkBlePermissions(): Boolean {
        // ... (misma lógica de antes)
        return true // Simplificado para brevedad, la lógica real permanece
    }

    private fun createNotificationChannel() { /* ... (misma lógica de antes) ... */ }
    private fun createNotification(): Notification { /* ... (misma lógica de antes) ... */ return NotificationCompat.Builder(this, "BitChatServiceChannel").build() } // Simplificado

    // --- Gestión de Peers ---
    /**
     * Centraliza la actualización de la información de un peer y notifica a los observadores.
     * Esta función debe ser llamada cada vez que el estado de un peer cambie.
     */
    private fun updatePeerInfo(
        deviceAddress: String,
        device: BluetoothDevice? = null,
        connectionState: BleOperationState? = null,
        isKnownGood: Boolean? = null,
        reconnectionAttempts: Int? = null,
        gatt: BluetoothGatt? = null,
        wantsNotifications: Boolean? = null
    ) {
        val now = System.currentTimeMillis()
        val peerInfo = knownPeers.computeIfAbsent(deviceAddress) {
            PeerConnectivityInfo(deviceAddress, device, BleOperationState.IDLE, now)
        }

        device?.let { peerInfo.bluetoothDevice = it }
        connectionState?.let { peerInfo.connectionState = it }
        isKnownGood?.let { peerInfo.isKnownGoodPeer = it }
        reconnectionAttempts?.let { peerInfo.reconnectionAttempts = it }
        gatt?.let { peerInfo.gatt = it }
        wantsNotifications?.let { peerInfo.wantsNotifications = it }
        peerInfo.lastSeenTimestamp = now

        Log.d(TAG, "Peer Info Actualizado para $deviceAddress: Estado=${peerInfo.connectionState}, Conocido=${peerInfo.isKnownGoodPeer}, Reintentos=${peerInfo.reconnectionAttempts}")
        _knownPeersStateFlow.value = HashMap(knownPeers) // Actualiza el StateFlow
    }

    // --- Lógica de Reconexión ---
    private fun handleConnectionFailure(deviceAddress: String, status: Int, isTimeout: Boolean = false) {
        Log.w(TAG, "GATT Cliente: Manejando fallo de conexión para $deviceAddress. Status: $status, Timeout: $isTimeout")
        gattClientConnections.remove(deviceAddress)?.apply { try { if (checkBlePermissions()) close() } catch (e: Exception) {} }

        val errorState = BleOperationState.ERROR_CONNECTION_FAILED(deviceAddress, status, isTimeout)
        updatePeerInfo(deviceAddress, connectionState = errorState)
        _bleOperationState.value = errorState // Actualiza el estado global si este era el intento activo

        val peerInfo = knownPeers[deviceAddress]
        if (peerInfo != null && peerInfo.isKnownGoodPeer) {
            scheduleReconnection(peerInfo)
        }
    }

    private fun scheduleReconnection(peerInfo: PeerConnectivityInfo) {
        if (peerInfo.reconnectionAttempts >= MAX_RECONNECTION_ATTEMPTS) {
            Log.w(TAG, "Máximos intentos de reconexión alcanzados para ${peerInfo.deviceAddress}. Rindiéndose.")
            updatePeerInfo(peerInfo.deviceAddress, connectionState = BleOperationState.ERROR_CONNECTION_FAILED(peerInfo.deviceAddress, null, false))
            return
        }

        val delayTime = (INITIAL_RECONNECTION_DELAY_MS * (2.0.pow(peerInfo.reconnectionAttempts))).toLong().coerceAtMost(MAX_RECONNECTION_DELAY_MS)
        Log.i(TAG, "Programando intento de reconexión ${peerInfo.reconnectionAttempts + 1} para ${peerInfo.deviceAddress} en ${delayTime}ms.")

        serviceScope.launch {
            delay(delayTime)
            if (isActive && bluetoothAdapter?.isEnabled == true && checkBlePermissions()) {
                 peerInfo.bluetoothDevice?.let {
                    Log.d(TAG, "Ejecutando reconexión programada para ${it.address}")
                    updatePeerInfo(it.address, reconnectionAttempts = peerInfo.reconnectionAttempts + 1)
                    connectToDevice(it, isReconnection = true)
                } ?: Log.w(TAG, "No se puede ejecutar reconexión para ${peerInfo.deviceAddress}, objeto BluetoothDevice es nulo.")
            } else {
                Log.w(TAG, "Omitiendo reconexión para ${peerInfo.deviceAddress}: servicio inactivo, BT apagado, o permisos perdidos.")
            }
        }
    }

    // --- GATT Callbacks y Operaciones BLE ---
    // (El resto de las funciones como startAdvertising, startScanning, gattServerCallback, etc.
    // ahora llaman a `updatePeerInfo` en los puntos apropiados para mantener el estado de `knownPeers` actualizado)

    // ... [El resto del código del servicio, modificado para usar updatePeerInfo]

    @Synchronized
    fun connectToDevice(device: BluetoothDevice, isReconnection: Boolean = false) {
        // ...
        val peerInfo = knownPeers.computeIfAbsent(device.address) {
            PeerConnectivityInfo(device.address, device, BleOperationState.IDLE)
        }
        // ...
        val state = if(isReconnection) BleOperationState.RECONNECTING_TO_PEER(device.address, peerInfo.reconnectionAttempts)
                    else BleOperationState.CONNECTING_TO_PEER(device.address)
        updatePeerInfo(device.address, device = device, connectionState = state)
        _bleOperationState.value = state
        // ...
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val deviceAddress = gatt.device.address
            val deviceName = try { if(checkBlePermissions()) gatt.device.name else "N/A" } catch (e: SecurityException) { "N/A" }
            Log.i(TAG, "GATT Cliente: onConnectionStateChange para $deviceAddress ($deviceName), Status: $status, NewState: $newState")

            activeGattContinuations.remove(deviceAddress)?.resume(if(newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) gatt else null, null)

            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    gattClientConnections[deviceAddress] = gatt
                    updatePeerInfo(deviceAddress, gatt, BleOperationState.CONNECTED_AS_CLIENT(deviceAddress, deviceName), true, 0)
                    _bleOperationState.value = BleOperationState.CONNECTED_AS_CLIENT(deviceAddress, deviceName)
                    // ... discover services ...
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    val peerInfo = knownPeers[deviceAddress]
                    Log.i(TAG, "GATT Cliente: Desconectado de $deviceAddress ($deviceName). Era conocido: ${peerInfo?.isKnownGoodPeer}")
                    try { if(checkBlePermissions()) gatt.close() } catch (e: Exception) {}
                    gattClientConnections.remove(deviceAddress)
                    updatePeerInfo(deviceAddress, connectionState = BleOperationState.IDLE)
                    if (peerInfo?.isKnownGoodPeer == true) {
                        scheduleReconnection(peerInfo)
                    }
                }
            } else {
                handleConnectionFailure(deviceAddress, status)
            }
        }
        // ... otros callbacks ...
    }
}
