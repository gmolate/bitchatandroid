package com.example.bitchat

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.example.bitchat.services.BluetoothMeshService
import com.example.bitchat.ui.screens.ChatScreen
import com.example.bitchat.ui.theme.BitChatTheme
import com.example.bitchat.viewmodel.ChatViewModel
import android.os.Build

class MainActivity : ComponentActivity() {

    private val chatViewModel: ChatViewModel by viewModels()
    private var bluetoothMeshService: BluetoothMeshService? = null
    private var isServiceBound = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? BluetoothMeshService.LocalBinder
            bluetoothMeshService = binder?.getService()
            isServiceBound = true
            if (bluetoothMeshService != null) {
                chatViewModel.setBluetoothServices(bluetoothMeshService!!) // Pass service to ViewModel
                Log.d("MainActivity", "BluetoothMeshService connected and set in ViewModel.")
                // Now that service is connected, you might trigger initial actions in ViewModel
                // if permissions are already granted, e.g., start scanning/advertising.
                // chatViewModel.onServiceReady() // Example method call
            } else {
                Log.e("MainActivity", "Failed to get service instance from binder.")
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            bluetoothMeshService = null
            isServiceBound = false
            Log.d("MainActivity", "BluetoothMeshService disconnected")
            // TODO: Optionally, notify ViewModel about service disconnection if it needs to clear states
            // chatViewModel.onServiceDisconnected()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BitChatTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ChatScreen(chatViewModel = chatViewModel) // Provide the ViewModel instance
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        // Start and bind to the BluetoothMeshService when the activity becomes visible
        Intent(this, BluetoothMeshService::class.java).also { intent ->
            // Use startForegroundService for API 26+ if the service calls startForeground()
            // This ensures the service can be promoted to foreground even if app is in background initially.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            // Bind to the service
            val success = bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
            Log.d("MainActivity", "Attempting to bind BluetoothMeshService in onStart. Success: $success")
        }
    }

    override fun onStop() {
        super.onStop()
        // Unbind from the service when the activity is no longer visible.
        // This allows the service to continue running in the background if it's a foreground service
        // but releases the activity's connection to it.
        if (isServiceBound) {
            try {
                unbindService(serviceConnection)
                isServiceBound = false
                Log.d("MainActivity", "BluetoothMeshService unbound in onStop.")
            } catch (e: IllegalArgumentException) {
                Log.e("MainActivity", "Error unbinding service in onStop (already unbound?): ${e.message}")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // If the activity is being destroyed and is not due to a configuration change,
        // and you want the service to stop when the app is fully closed, you might stop it here.
        // However, for a mesh networking app, the service might be intended to run longer.
        // For now, we only unbind. The service itself manages its lifecycle (e.g., via stopSelf() or stopService()).
        Log.d("MainActivity", "onDestroy called.")
    }
}
