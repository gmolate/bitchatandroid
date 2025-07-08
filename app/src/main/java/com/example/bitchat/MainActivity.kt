package com.example.bitchat

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.bitchat.ui.theme.BitChatTheme // Assuming this will be created

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BitChatTheme { // AppTheme composable
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    // Surface(
                    //    modifier = Modifier.fillMaxSize(),
                    //    color = MaterialTheme.colorScheme.background
                    // ) {
                    //    Greeting("Android")
                    // }
                    ChatScreen() // Integrate ChatScreen
                }
            }
        }
    }
}

// @Composable
// fun Greeting(name: String, modifier: Modifier = Modifier) {
//    Text(
//        text = "Hello $name from BitChat!",
//        modifier = modifier
//    )
// }

// @Preview(showBackground = true)
// @Composable
// fun GreetingPreview() {
//    BitChatTheme {
//        Greeting("Android")
//    }
// }
