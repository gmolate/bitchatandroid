package com.example.bitchat.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.bitchat.ui.theme.BitChatTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateChannelScreen(
    onNavigateBack: () -> Unit,
    onCreateChannel: (channelName: String, isPrivate: Boolean, passwordAttempt: String?) -> Unit
) {
    var channelName by remember { mutableStateOf("") }
    // TODO: Add state for isPrivate (Switch) and password (TextField, visible if isPrivate)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Create New Channel") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
                // TODO: Add navigation icon to go back if needed, or rely on system back
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("Create a New Channel", style = MaterialTheme.typography.headlineSmall)
            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = channelName,
                onValueChange = { channelName = it },
                label = { Text("Channel Name (e.g., #topic)") },
                singleLine = true
            )
            Spacer(modifier = Modifier.height(16.dp))

            // TODO: Add UI elements for:
            // 1. Toggle for private channel (Switch Composable)
            // 2. TextField for password if channel is private
            // 3. (Future) Multi-select list for members from known peers

            Button(
                onClick = {
                    if (channelName.isNotBlank()) {
                        // For now, assuming public channel without password
                        onCreateChannel(channelName, false, null)
                    }
                },
                enabled = channelName.isNotBlank()
            ) {
                Text("Create Channel")
            }
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = onNavigateBack) {
                Text("Cancel")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun CreateChannelScreenPreview() {
    BitChatTheme {
        CreateChannelScreen(
            onNavigateBack = {},
            onCreateChannel = { name, isPrivate, pw -> }
        )
    }
}
