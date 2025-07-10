package com.example.bitchat.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.bitchat.models.ChannelInfo
import com.example.bitchat.ui.theme.BitChatTheme
import com.example.bitchat.viewmodel.ChatViewModel // Assuming access to ChatViewModel for preview or direct use

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelListScreen(
    chatViewModel: ChatViewModel, // Or a dedicated ChannelViewModel
    onNavigateToChannel: (channelName: String) -> Unit,
    onNavigateToCreateChannel: () -> Unit
) {
    val channels by chatViewModel.allChannels.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Channels") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onNavigateToCreateChannel) {
                Icon(Icons.Filled.Add, contentDescription = "Create Channel")
            }
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            if (channels.isEmpty()) {
                Text(
                    "No channels found. Create one!",
                    modifier = Modifier.padding(16.dp).fillMaxWidth(),
                    style = MaterialTheme.typography.bodyLarge
                )
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(channels, key = { it.id }) { channel ->
                        ChannelListItem(channel = channel, onClick = {
                            onNavigateToChannel(channel.name)
                        })
                    }
                }
            }
        }
    }
}

@Composable
fun ChannelListItem(channel: ChannelInfo, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(channel.name, style = MaterialTheme.typography.titleMedium) },
        supportingContent = { Text("Members: ${channel.memberPeerIds.size} | Last activity: ${channel.lastActivityTimestamp}") }, // Placeholder for actual activity string
        modifier = Modifier.clickable(onClick = onClick)
        // TODO: Add unread count indicator, private channel icon
    )
}

@Preview(showBackground = true)
@Composable
fun ChannelListScreenPreview() {
    // This preview is conceptual as it needs a running ViewModel with state.
    // For a real preview, you'd mock the ViewModel or provide sample data.
    val mockChannels = listOf(
        ChannelInfo(id="1", name="#general", memberPeerIds = listOf("peer1", "peer2"), lastActivityTimestamp = System.currentTimeMillis() - 10000),
        ChannelInfo(id="2", name="#random", memberPeerIds = listOf("peer1"), lastActivityTimestamp = System.currentTimeMillis() - 200000, isPrivate = true),
        ChannelInfo(id="3", name="Direct: Alice", memberPeerIds = listOf("alice_id"), lastActivityTimestamp = System.currentTimeMillis(), isPrivate = true)
    )
    // A simple mock ViewModel for preview purposes:
    class MockChatViewModel : ChatViewModel(Application()) { // Needs Application context
        override val allChannels: StateFlow<List<ChannelInfo>> = MutableStateFlow(mockChannels)
    }

    BitChatTheme {
        // ChannelListScreen(chatViewModel = MockChatViewModel(), onNavigateToChannel = {}, onNavigateToCreateChannel = {})
        Text("ChannelListScreen Preview (Conceptual - Run on device/emulator with ViewModel)")
    }
}
