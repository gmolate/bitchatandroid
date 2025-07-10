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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.bitchat.ui.theme.BitChatTheme
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Switch // Import Switch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateChannelScreen(
    onNavigateBack: () -> Unit,
    onCreateChannel: (channelName: String, isPrivate: Boolean, passwordAttempt: String?) -> Unit
) {
    var channelName by remember { mutableStateOf("") }
    var isPrivate by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") } // For password confirmation
    var passwordError by remember { mutableStateOf<String?>(null) }

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
                singleLine = true,
                label = { Text("Channel Name (e.g., #topic or MyGroup)") }
            )
            Spacer(modifier = Modifier.height(16.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Private Channel")
                Spacer(Modifier.weight(1f))
                Switch(
                    checked = isPrivate,
                    onCheckedChange = {
                        isPrivate = it
                        if (!it) { // Clear password if channel becomes public
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
                    isError = passwordError != null
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = confirmPassword,
                    onValueChange = { confirmPassword = it; passwordError = null },
                    label = { Text("Confirm Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    isError = passwordError != null
                )
                passwordError?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // Placeholder for member selection - In a real app, this would be a list or a way to search/add peers.
            Text("Member selection (TODO)", style = MaterialTheme.typography.bodySmall)
            Spacer(modifier = Modifier.height(16.dp))


            Button(
                onClick = {
                    val finalChannelName = if (channelName.startsWith("#") || channelName.contains(":")) channelName else "#$channelName"
                    if (finalChannelName.isBlank()) {
                        // Should ideally have validation directly on TextField
                        return@Button
                    }
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
                    onCreateChannel(finalChannelName, isPrivate, if (isPrivate) password else null)
                },
                enabled = channelName.isNotBlank() && (!isPrivate || (password.isNotBlank() && confirmPassword.isNotBlank() && passwordError == null))
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

@Preview(showBackground = true, name="Create Public Channel")
@Composable
fun CreateChannelScreenPreviewPublic() {
    BitChatTheme {
        CreateChannelScreen(
            onNavigateBack = {},
            onCreateChannel = { name, isPrivate, pw -> }
        )
    }
}

@Preview(showBackground = true, name="Create Private Channel")
@Composable
fun CreateChannelScreenPreviewPrivate() {
    var isPrivateState by remember { mutableStateOf(true) } // To show private fields
    // This preview is a bit limited as it can't fully interact with the internal state for isPrivate
    // but it helps visualize the layout.
    BitChatTheme {
         Column(modifier = Modifier.padding(16.dp)) {
            OutlinedTextField(value = "#secure-room", onValueChange = {}, label = {Text("Channel Name")})
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Private Channel")
                Spacer(Modifier.weight(1f))
                Switch(checked = isPrivateState, onCheckedChange = {isPrivateState = it})
            }
            if(isPrivateState){
                OutlinedTextField(value = "password", onValueChange = {}, label = {Text("Password")})
                OutlinedTextField(value = "password", onValueChange = {}, label = {Text("Confirm Password")})
            }
            Button(onClick={}){ Text("Create Channel")}
        }
    }
}
