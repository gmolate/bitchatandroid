package com.example.bitchat.ui.screens

import android.Manifest
import android.app.Application
import android.os.Build
import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.bitchat.viewmodel.ChatViewModel
import com.example.bitchat.viewmodel.UiMessage
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.MultiplePermissionsState
import com.google.accompanist.permissions.rememberMultiplePermissionsState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

/**
 * The main chat screen Composable for the BitChat application.
 * This screen is responsible for displaying chat messages, handling user input,
 * managing UI state related to the chat, and requesting necessary permissions.
 *
 * @param chatViewModel The [ChatViewModel] instance associated with this screen, typically provided by Jetpack Compose's `viewModel()` delegate.
 */
@OptIn(ExperimentalPermissionsApi::class) // For Accompanist Permissions
@Composable
fun ChatScreen(chatViewModel: ChatViewModel = viewModel()) {
    // Collect UI state from the ViewModel using StateFlow and collectAsState
    val messages by chatViewModel.messages.collectAsState()
    val currentChannel by chatViewModel.currentChannel.collectAsState()
    val inputText by chatViewModel.inputText.collectAsState()
    val displayName by chatViewModel.displayName.collectAsState()
    val connectedPeersCount by chatViewModel.connectedPeers.map { it.size }.collectAsState(initial = 0)

    val context = LocalContext.current // Get current context
    val lazyListState = rememberLazyListState() // State for controlling and observing the LazyColumn
    val coroutineScope = rememberCoroutineScope() // Scope for launching coroutines from Composables

    // --- Permissions Handling ---
    // Define required permissions based on Android SDK version.
    val blePermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) { // Android 12 (API 31) and above
        listOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.ACCESS_FINE_LOCATION // Still recommended for reliable scanning even with `neverForLocation`
        )
    } else { // Pre-Android 12
        listOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    }
    val notificationPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) { // Android 13 (API 33) and above
        listOf(Manifest.permission.POST_NOTIFICATIONS)
    } else {
        emptyList()
    }
    val allPermissions = blePermissions + notificationPermission

    // Remember the state of multiple permissions using Accompanist library.
    val permissionsState = rememberMultiplePermissionsState(permissions = allPermissions)

    // Effect that launches when `allPermissionsGranted` changes.
    // Used to automatically request permissions if they are not granted and rationale isn't needed.
    LaunchedEffect(key1 = permissionsState.allPermissionsGranted) {
        if (!permissionsState.allPermissionsGranted && !permissionsState.shouldShowRationale) {
            Log.d("ChatScreen", "Permissions not granted and no rationale shown, launching request.")
            permissionsState.launchMultiplePermissionRequest()
        }
        // TODO: If permissions are granted, the ViewModel should ideally be notified
        // to initialize or start Bluetooth services if they haven't been started yet.
        // This could involve observing permissionsState.allPermissionsGranted in the ViewModel
        // or calling a specific ViewModel method from here post-grant.
    }

    // Effect to scroll to the bottom of the message list when new messages are added.
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            coroutineScope.launch {
                lazyListState.animateScrollToItem(messages.size - 1)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("BitChat: $currentChannel ($displayName) - Peers: $connectedPeersCount") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
                // TODO: Implement TopAppBar actions:
                //  - Settings icon button
                //  - Peer list icon button
                //  - Channel list/management icon button
                //  - Manual Start/Stop Scan/Advertise toggle (for debugging/advanced use)
            )
        },
        bottomBar = {
            MessageInputRow(
                text = inputText,
                onTextChanged = { chatViewModel.onInputTextChanged(it) },
                onSendClicked = {
                    if (inputText.isNotBlank()) { // Prevent sending empty messages
                        chatViewModel.sendMessage(inputText)
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues) // Apply padding from Scaffold (for TopAppBar and BottomBar)
                .padding(horizontal = 8.dp) // Overall horizontal padding for the content area
        ) {
            // If not all permissions are granted, display the permission request UI.
            if (!permissionsState.allPermissionsGranted) {
                PermissionRequestUI(permissionsState = permissionsState)
            } else {
                 // Message List Area
                LazyColumn(
                    state = lazyListState,
                    modifier = Modifier.weight(1f), // Makes the LazyColumn take up available vertical space
                    verticalArrangement = Arrangement.spacedBy(8.dp) // Adds space between message items
                ) {
                    items(messages, key = { it.id }) { message -> // Use message ID as a stable key
                        MessageItem(message = message)
                    }
                }
            }
        }
    }
}

/**
 * Composable function to display the UI for requesting necessary permissions.
 * It explains why permissions are needed and provides a button to grant them.
 *
 * @param permissionsState The [MultiplePermissionsState] from Accompanist Permissions library.
 */
@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun PermissionRequestUI(permissionsState: MultiplePermissionsState) {
    Column(
        modifier = Modifier
            .fillMaxSize() // Takes full screen if permissions not granted
            .padding(all = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Permissions Required",
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.padding(bottom = 16.dp)
        )
        Text(
            text = "BitChat needs Bluetooth, Location, and (on newer Android versions) Notification permissions to function correctly. " +
                   "Bluetooth is essential for discovering and communicating with nearby devices in the mesh network. " +
                   "Location access is required by the Android system for Bluetooth scanning operations. " +
                   "Notifications allow you to receive alerts for new messages when the app is in the background.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(bottom = 16.dp)
        )
        // Show rationale if permissions were previously denied.
        if (permissionsState.shouldShowRationale) {
             Text(
                text = "Some permissions were denied. Please grant them for the app to work as expected.",
                 style = MaterialTheme.typography.bodySmall,
                 color = MaterialTheme.colorScheme.error, // Use error color for emphasis
                 modifier = Modifier.padding(bottom = 8.dp)
            )
        }
        Button(onClick = { permissionsState.launchMultiplePermissionRequest() }) {
            Text("Grant Permissions")
        }
        // TODO: Consider adding a button/link to open app settings if permissions are permanently denied by the user.
    }
}


/**
 * Composable function for displaying a single chat message item.
 * It differentiates messages from the current user and other users by alignment and color.
 *
 * @param message The [UiMessage] object containing the data for the message to be displayed.
 */
@Composable
fun MessageItem(message: UiMessage) {
    // Formatter for timestamp, remembered to avoid recomposition on every message item.
    val sdf = remember { SimpleDateFormat("HH:mm:ss, MMM dd", Locale.getDefault()) }
    val timeString = sdf.format(Date(message.timestamp))

    // Determine alignment and colors based on whether the message is from the current user.
    val alignment = if (message.isFromCurrentUser) Alignment.End else Alignment.Start
    val backgroundColor = if (message.isFromCurrentUser) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.secondaryContainer
    val textColor = if (message.isFromCurrentUser) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSecondaryContainer

    Column(
        modifier = Modifier
            .fillMaxWidth() // Take full width to allow alignment within it
            .padding(vertical = 4.dp),
        horizontalAlignment = alignment // Align the content (message bubble) to start or end
    ) {
        // Display sender's name above the message bubble for messages not from the current user.
        // TODO: Potentially show sender name only if it's different from the previous message's sender (if not current user).
        if (!message.isFromCurrentUser) {
            Text(
                text = message.senderName,
                style = MaterialTheme.typography.labelMedium, // Using labelMedium for sender name
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant, // A less prominent color for sender name
                modifier = Modifier.padding(start = if (alignment == Alignment.Start) 8.dp else 0.dp, end = if (alignment == Alignment.End) 8.dp else 0.dp, bottom = 2.dp)
            )
        }

        Surface( // Represents the message bubble
            shape = MaterialTheme.shapes.medium, // Apply rounded corners from the theme
            color = backgroundColor,
            tonalElevation = 1.dp, // Subtle elevation for a card-like appearance
            modifier = Modifier.fillMaxWidth(0.85f) // Message bubble takes up to 85% of the available width
        ) {
            Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) { // Inner padding for content
                Text(
                    text = message.text,
                    style = MaterialTheme.typography.bodyLarge, // Use bodyLarge for message text for readability
                    color = textColor
                )
                Spacer(modifier = Modifier.height(4.dp)) // Space between text and timestamp
                Text( // Timestamp and channel information
                    text = "$timeString on ${message.channel}",
                    style = MaterialTheme.typography.bodySmall, // Smaller text for metadata
                    fontStyle = FontStyle.Italic,
                    fontSize = 10.sp, // Explicitly small font size
                    color = textColor.copy(alpha = 0.7f) // Slightly faded color for less emphasis
                )
            }
        }
    }
}

/**
 * Composable function for the message input field and send button row.
 *
 * @param text The current text in the input field, observed from ViewModel.
 * @param onTextChanged Callback function invoked when the input text changes.
 * @param onSendClicked Callback function invoked when the send button is clicked.
 */
@OptIn(ExperimentalMaterial3Api::class) // Required for OutlinedTextField
@Composable
fun MessageInputRow(
    text: String,
    onTextChanged: (String) -> Unit,
    onSendClicked: () -> Unit
) {
    Surface(tonalElevation = 3.dp) { // Provides a slight visual separation for the input row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp), // Padding around the input row
            verticalAlignment = Alignment.CenterVertically // Align items vertically in the center
        ) {
            OutlinedTextField(
                value = text,
                onValueChange = onTextChanged,
                modifier = Modifier.weight(1f), // TextField takes available horizontal space
                placeholder = { Text("Type a message or /command") },
                singleLine = true, // For a single-line input field
                // TODO: Consider using `KeyboardOptions` and `KeyboardActions` for 'Send' IME action
                // keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                // keyboardActions = KeyboardActions(onSend = { if (text.isNotBlank()) onSendClicked() }),
                textStyle = MaterialTheme.typography.bodyLarge // Consistent text style
            )
            Spacer(modifier = Modifier.width(8.dp)) // Space between TextField and Button
            Button(
                onClick = onSendClicked,
                enabled = text.isNotBlank(), // Enable button only if there is text to send
                modifier = Modifier.height(IntrinsicSize.Min) // Attempt to match TextField height (may need adjustment)
            ) {
                Text("SEND")
            }
        }
    }
}

// --- Preview Functions ---

/**
 * Preview for the ChatScreen in Light Mode.
 * Uses a mock ChatViewModel with sample messages for UI development and testing.
 */
@Preview(showBackground = true, name = "Chat Screen - Light Mode")
@Composable
fun ChatScreenPreviewLight() {
    val previewViewModel = ChatViewModel(Application())
    LaunchedEffect(Unit) {
        try {
            // Using reflection to set mock messages for preview. This is a common workaround.
            // Not for production code.
            val messagesField = ChatViewModel::class.java.getDeclaredField("_messages")
            messagesField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val messagesFlow = messagesField.get(previewViewModel) as MutableStateFlow<List<UiMessage>>
            messagesFlow.value = listOf(
                UiMessage(senderName = "Alice", text = "Hello Bob! This is a longer message to test how it wraps within the bubble and fits the screen.", isFromCurrentUser = false, channel = "#general", timestamp = System.currentTimeMillis() - 200000),
                UiMessage(senderName = "Bob (Me)", text = "Hi Alice! How are you doing today? I'm testing my message bubble.", isFromCurrentUser = true, channel = "#general", timestamp = System.currentTimeMillis() - 100000),
                UiMessage(senderName = "Alice", text = "I'm good, thanks! Just testing this new chat app. It looks pretty cool!", isFromCurrentUser = false, channel = "#general", timestamp = System.currentTimeMillis() - 50000),
                UiMessage(senderName = "System", text = "User 'Charlie' joined #general.", isFromCurrentUser = false, channel = "#general", timestamp = System.currentTimeMillis() - 40000)
            )
        } catch (e: Exception) {
            Log.e("ChatScreenPreview", "Error setting mock messages for light preview: ${e.message}")
        }
    }

    com.example.bitchat.ui.theme.BitChatTheme(darkTheme = false) { // Explicitly set light theme
        ChatScreen(chatViewModel = previewViewModel)
    }
}

/**
 * Preview for the ChatScreen in Dark Mode.
 */
@Preview(showBackground = true, name = "Chat Screen - Dark Mode")
@Composable
fun ChatScreenPreviewDark() {
     val previewViewModel = ChatViewModel(Application())
    LaunchedEffect(Unit) {
        try {
            val messagesField = ChatViewModel::class.java.getDeclaredField("_messages")
            messagesField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val messagesFlow = messagesField.get(previewViewModel) as MutableStateFlow<List<UiMessage>>
            messagesFlow.value = listOf(
                UiMessage(senderName = "Alice", text = "Dark mode test message!", isFromCurrentUser = false, channel = "#darktheme", timestamp = System.currentTimeMillis() - 10000),
                UiMessage(senderName = "Bob (Me)", text = "This looks good in dark mode too!", isFromCurrentUser = true, channel = "#darktheme", timestamp = System.currentTimeMillis())
            )
        } catch (e: Exception) {
            Log.e("ChatScreenPreview", "Error setting mock messages for dark preview: ${e.message}")
        }
    }
    com.example.bitchat.ui.theme.BitChatTheme(darkTheme = true) { // Explicitly set dark theme
        ChatScreen(chatViewModel = previewViewModel)
    }
}

// Helper function for reflection, typically used in previews for accessing private fields.
// Not recommended for production code due to its brittleness and violation of encapsulation.
// fun Any.GetType(): Class<*> = this::class.java // Already present in original, kept if needed elsewhere.
// Note: The GetType() helper was removed as it's not directly used in these refined previews.
// The reflection for _messages is done directly within the LaunchedEffect.
