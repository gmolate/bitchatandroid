package com.example.bitchat.data

import android.util.Log
import com.example.bitchat.services.DataStorageService
import com.example.bitchat.viewmodel.UiMessage // Assuming UiMessage is suitable for persistence directly for now
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.util.UUID

/**
 * Repository for handling message data operations.
 * It abstracts the data source (currently DataStorageService with DataStore) from the ViewModel.
 *
 * @param dataStorageService The service responsible for actual data persistence.
 */
class MessageRepository(private val dataStorageService: DataStorageService) {

    companion object {
        private const val TAG = "MessageRepository"
    }

    /**
     * Saves a message to the persistent storage for a specific channel.
     *
     * @param channelName The name of the channel.
     * @param message The UiMessage to save.
     */
    suspend fun saveMessage(channelName: String, message: UiMessage) {
        try {
            dataStorageService.addMessageToChannel(channelName, message)
            Log.d(TAG, "Message saved for channel '$channelName': ${message.id}")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving message for channel '$channelName': ${e.message}", e)
            // Optionally, rethrow or handle error in a way that ViewModel can observe
        }
    }

    /**
     * Retrieves all messages for a specific channel as a Flow.
     * Messages are sorted by timestamp.
     *
     * @param channelName The name of the channel.
     * @return A Flow emitting a list of UiMessages for the channel.
     */
    fun getMessagesForChannel(channelName: String): Flow<List<UiMessage>> {
        Log.d(TAG, "Getting messages for channel '$channelName'")
        return dataStorageService.getMessagesForChannel(channelName)
            .map { messages ->
                // DataStore might return them in insertion order or unsorted; ensure sorted by timestamp.
                messages.sortedBy { it.timestamp }
            }
            .catch { e ->
                Log.e(TAG, "Error getting messages for channel '$channelName': ${e.message}", e)
                emit(emptyList()) // Emit an empty list on error to prevent crash
            }
    }

    /**
     * Clears all messages for a specific channel.
     *
     * @param channelName The name of the channel to clear.
     */
    suspend fun clearMessagesForChannel(channelName: String) {
        try {
            dataStorageService.clearMessagesForChannel(channelName)
            Log.d(TAG, "Messages cleared for channel '$channelName'")
        } catch (e: Exception) {
            Log.e(TAG, "Error clearing messages for channel '$channelName': ${e.message}", e)
        }
    }

    /**
     * Clears all messages from all channels.
     * (Use with caution)
     */
    suspend fun clearAllMessages() {
        try {
            dataStorageService.clearAllMessages() // This method needs to be added to DataStorageService
            Log.d(TAG, "All messages cleared from DataStore.")
        } catch (e: Exception) {
            Log.e(TAG, "Error clearing all messages: ${e.message}", e)
        }
    }

    /**
     * Retrieves a single message by its ID.
     * Note: This might be inefficient with the current DataStore approach if not indexed.
     * This is more of a placeholder for what a Room-based repository could easily do.
     *
     * @param messageId The UUID of the message to retrieve.
     * @return The UiMessage if found, null otherwise.
     */
    suspend fun getMessageById(channelName: String, messageId: UUID): UiMessage? {
        // This is inefficient with the current list-in-DataStore approach.
        // It requires fetching all messages for the channel and then filtering.
        return dataStorageService.getMessagesForChannel(channelName).firstOrNull()?.find { it.id == messageId }
    }
}
