package com.example.bitchat.ui.screens

import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.bitchat.ui.theme.BitChatTheme
import com.example.bitchat.viewmodel.ChatViewModel
import com.example.bitchat.viewmodel.PeerDisplayInfo
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateChannelScreen(
    chatViewModel: ChatViewModel, // Pass the ViewModel to get available peers
    onNavigateBack: () -> Unit,
    onCreateChannel: (channelName: String, isPrivate: Boolean, passwordAttempt: String?, memberIds: List<String>) -> Unit
) {
    var channelName by remember { mutableStateOf("") }
    var isPrivate by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var passwordError by remember { mutableStateOf<String?>(null) }

    val availablePeers by chatViewModel.availablePeers.collectAsState()
    val selectedPeerIds = remember { mutableStateListOf<String>() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Create New Channel") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("Create a New Channel", style = MaterialTheme.typography.headlineSmall)
            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = channelName,
                onValueChange = { channelName = it },
                label = { Text("Channel Name (e.g., #work-project)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(16.dp))

            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Text("Private Channel")
                Spacer(Modifier.weight(1f))
                Switch(
                    checked = isPrivate,
                    onCheckedChange = {
                        isPrivate = it
                        if (!it) {
                            password = ""
                            confirmPassword = ""
                            passwordError = null
                        }
                    }
                )
            }
            Spacer(modifier = Modifier.height(16.dp))

            if (isPrivate) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it; passwordError = null },
                    label = { Text("Password (min 6 chars)") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    isError = passwordError != null,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = confirmPassword,
                    onValueChange = { confirmPassword = it; passwordError = null },
                    label = { Text("Confirm Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    isError = passwordError != null,
                    modifier = Modifier.fillMaxWidth()
                )
                passwordError?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // --- Member Selection ---
            Text("Select Members", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(8.dp))
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 200.dp) // Constrain height of the list
            ) {
                if (availablePeers.isEmpty()) {
                    item {
                        Text("No other peers discovered yet.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 8.dp))
                    }
                } else {
                    items(availablePeers, key = { it.peerId }) { peer ->
                        PeerSelectionItem(
                            peer = peer,
                            isSelected = selectedPeerIds.contains(peer.peerId),
                            onSelectionChanged = {
                                if (selectedPeerIds.contains(peer.peerId)) {
                                    selectedPeerIds.remove(peer.peerId)
                                } else {
                                    selectedPeerIds.add(peer.peerId)
                                }
                            }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.weight(1f)) // Push buttons to bottom

            Button(
                onClick = {
                    val finalChannelName = if (channelName.startsWith("#") || channelName.contains(":")) channelName else "#$channelName"
                    if (finalChannelName.isBlank()) return@Button
                    if (isPrivate) {
                        if (password.length < 6) {
                            passwordError = "Password must be at least 6 characters."
                            return@Button
                        }
                        if (password != confirmPassword) {
                            passwordError = "Passwords do not match."
                            return@Button
                        }
                    }
                    onCreateChannel(finalChannelName, isPrivate, if (isPrivate) password else null, selectedPeerIds.toList())
                },
                enabled = channelName.isNotBlank() && (!isPrivate || (password.isNotBlank() && confirmPassword.isNotBlank() && passwordError == null)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Create Channel")
            }
            Spacer(modifier = Modifier.height(8.dp))
            Button(onClick = onNavigateBack, modifier = Modifier.fillMaxWidth()) {
                Text("Cancel")
            }
        }
    }
}

@Composable
fun PeerSelectionItem(
    peer: PeerDisplayInfo,
    isSelected: Boolean,
    onSelectionChanged: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelectionChanged(!isSelected) }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(
            checked = isSelected,
            onCheckedChange = null // Click is handled by the Row
        )
        Spacer(modifier = Modifier.width(16.dp))
        Column {
            Text(peer.displayName, style = MaterialTheme.typography.bodyLarge)
            Text(
                if (peer.isOnline) "Online" else "Offline",
                style = MaterialTheme.typography.bodySmall,
                color = if (peer.isOnline) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun CreateChannelScreenPreview() {
    class PreviewChatViewModel(app: Application) : ChatViewModel(app) {
         override val availablePeers: StateFlow<List<PeerDisplayInfo>> = MutableStateFlow(listOf(
             PeerDisplayInfo("peer1_addr", "Alice", true),
             PeerDisplayInfo("peer2_addr", "Bob", false),
             PeerDisplayInfo("peer3_addr", "Charlie", true)
         ))
    }

    BitChatTheme {
        CreateChannelScreen(
            chatViewModel = PreviewChatViewModel(LocalContext.current.applicationContext as Application),
            onNavigateBack = {},
            onCreateChannel = { _, _, _, _ -> }
        )
    }
}
