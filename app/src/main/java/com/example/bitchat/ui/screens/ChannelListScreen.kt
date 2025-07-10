package com.example.bitchat.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock // For private channel icon
import androidx.compose.material3.Badge // For unread count
import androidx.compose.material3.BadgedBox
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.bitchat.models.ChannelInfo
import com.example.bitchat.ui.theme.BitChatTheme
import com.example.bitchat.viewmodel.ChatViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import android.app.Application // For Preview ViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelListScreen(
    chatViewModel: ChatViewModel,
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
                Column(
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        "No channels available.",
                        style = MaterialTheme.typography.bodyLarge
                    )
                    Text(
                        "Tap the '+' button to create a new channel.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelListItem(channel: ChannelInfo, onClick: () -> Unit) {
    val sdf = remember { SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()) }
    val lastActivityFormatted = remember(channel.lastActivityTimestamp) {
        if (channel.lastActivityTimestamp > 0) sdf.format(Date(channel.lastActivityTimestamp)) else "N/A"
    }

    ListItem(
        headlineContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (channel.isPrivate) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = "Private Channel",
                        modifier = Modifier.size(18.dp).padding(end = 4.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(channel.name, style = MaterialTheme.typography.titleMedium)
            }
        },
        supportingContent = {
            Text(
                "Members: ${channel.memberPeerIds.size} | Last activity: $lastActivityFormatted",
                style = MaterialTheme.typography.bodySmall
            )
        },
        trailingContent = {
            if (channel.unreadCount > 0) {
                BadgedBox(badge = { Badge { Text("${channel.unreadCount}") } }) {
                    // Icon(Icons.Filled.ChatBubbleOutline, contentDescription = "Unread messages") // Optional icon inside badge
                }
            }
        },
        modifier = Modifier.clickable(onClick = onClick)
    )
}

@Preview(showBackground = true)
@Composable
fun ChannelListScreenPreview() {
    val mockChannels = listOf(
        ChannelInfo(id="1", name="#general", memberPeerIds = listOf("peer1", "peer2"), lastActivityTimestamp = System.currentTimeMillis() - 10000, unreadCount = 3),
        ChannelInfo(id="2", name="#random", memberPeerIds = listOf("peer1"), lastActivityTimestamp = System.currentTimeMillis() - 200000, isPrivate = true),
        ChannelInfo(id="3", name="Direct: Alice", memberPeerIds = listOf("alice_id"), lastActivityTimestamp = System.currentTimeMillis(), isPrivate = true, unreadCount = 1)
    )

    // A simple mock ChatViewModel for preview purposes.
    // In a real app with Hilt/Koin, you might provide a @Preview ViewModel.
    class PreviewChatViewModel(app: Application) : ChatViewModel(app) {
         override val allChannels: StateFlow<List<ChannelInfo>> = MutableStateFlow(mockChannels)
    }

    BitChatTheme {
        ChannelListScreen(
            // This requires Application context for ChatViewModel.
            // In previews, this can be tricky. Pass a LocalContext.current.applicationContext if available.
            // For simplicity, if running this preview in an environment that can provide Application, it works.
            // Otherwise, a more elaborate preview setup with a fake ViewModel might be needed.
            chatViewModel = PreviewChatViewModel(LocalContext.current.applicationContext as Application),
            onNavigateToChannel = {},
            onNavigateToCreateChannel = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun ChannelListItemPreview() {
    BitChatTheme {
        Column {
            ChannelListItem(
                channel = ChannelInfo(id="1", name="#general", memberPeerIds = listOf("p1"), lastActivityTimestamp = System.currentTimeMillis() - 5000, unreadCount = 5),
                onClick = {}
            )
            ChannelListItem(
                channel = ChannelInfo(id="2", name="#private-chat", memberPeerIds = listOf("p1", "p2"), isPrivate = true, lastActivityTimestamp = System.currentTimeMillis() - 1000000),
                onClick = {}
            )
            ChannelListItem(
                channel = ChannelInfo(id="3", name="#very-long-channel-name-example-to-see-how-it-fits", memberPeerIds = emptyList(), lastActivityTimestamp = 0),
                onClick = {}
            )
        }
    }
}
