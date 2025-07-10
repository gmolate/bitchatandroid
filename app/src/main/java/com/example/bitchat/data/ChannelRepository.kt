package com.example.bitchat.data

import android.util.Log
import com.example.bitchat.models.ChannelInfo
import com.example.bitchat.services.DataStorageService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class ChannelRepository(private val dataStorageService: DataStorageService) {

    companion object {
        private const val TAG = "ChannelRepository"
    }

    private val channelsMutex = Mutex() // To protect concurrent modifications to the list

    // Exposes a flow of the list of channels
    val allChannelsFlow: Flow<List<ChannelInfo>> = dataStorageService.channelsFlow

    /**
     * Retrieves all channels, sorted by last activity (most recent first).
     */
    suspend fun getAllChannelsSorted(): List<ChannelInfo> {
        return dataStorageService.getChannels().sortedByDescending { it.lastActivityTimestamp }
    }

    /**
     * Adds a new channel to the list if a channel with the same ID doesn't already exist.
     * If it exists, it updates it (though full update logic might be more complex).
     * @param channelInfo The channel to add or update.
     */
    suspend fun addOrUpdateChannel(channelInfo: ChannelInfo) {
        channelsMutex.withLock {
            val channels = dataStorageService.getChannels().toMutableList()
            val existingIndex = channels.indexOfFirst { it.id == channelInfo.id }
            if (existingIndex != -1) {
                // Update existing channel (simple replacement for now, could be more granular)
                channels[existingIndex] = channelInfo
                Log.i(TAG, "Updating existing channel: ${channelInfo.name} (ID: ${channelInfo.id})")
            } else {
                channels.add(channelInfo)
                Log.i(TAG, "Adding new channel: ${channelInfo.name} (ID: ${channelInfo.id})")
            }
            dataStorageService.saveChannels(channels.sortedByDescending { it.lastActivityTimestamp })
        }
    }

    /**
     * Retrieves a specific channel by its ID.
     * @param channelId The ID of the channel to retrieve.
     * @return The ChannelInfo object if found, null otherwise.
     */
    suspend fun getChannelById(channelId: String): ChannelInfo? {
        return dataStorageService.getChannels().find { it.id == channelId }.also {
            if (it != null) {
                Log.d(TAG, "Channel found by ID '$channelId': ${it.name}")
            } else {
                Log.w(TAG, "Channel with ID '$channelId' not found.")
            }
        }
    }

    /**
     * Retrieves a specific channel by its name.
     * Case-insensitive search.
     * @param channelName The name of the channel to retrieve.
     * @return The ChannelInfo object if found, null otherwise.
     */
    suspend fun getChannelByName(channelName: String): ChannelInfo? {
        return dataStorageService.getChannels().find { it.name.equals(channelName, ignoreCase = true) }.also {
            if (it != null) {
                Log.d(TAG, "Channel found by name '$channelName': ID ${it.id}")
            } else {
                Log.w(TAG, "Channel with name '$channelName' not found.")
            }
        }
    }


    /**
     * Deletes a channel by its ID.
     * @param channelId The ID of the channel to delete.
     */
    suspend fun deleteChannel(channelId: String) {
        channelsMutex.withLock {
            val channels = dataStorageService.getChannels().toMutableList()
            val removed = channels.removeAll { it.id == channelId }
            if (removed) {
                dataStorageService.saveChannels(channels)
                Log.i(TAG, "Channel with ID '$channelId' deleted.")
            } else {
                Log.w(TAG, "Attempted to delete channel with ID '$channelId', but it was not found.")
            }
        }
    }

    /**
     * Updates the last activity timestamp for a given channel.
     * If the channel doesn't exist, this operation does nothing.
     * @param channelId The ID of the channel to update.
     * @param timestamp The new timestamp for the last activity.
     */
    suspend fun updateChannelLastActivity(channelId: String, timestamp: Long = System.currentTimeMillis()) {
        channelsMutex.withLock {
            val channels = dataStorageService.getChannels().toMutableList()
            val index = channels.indexOfFirst { it.id == channelId }
            if (index != -1) {
                channels[index] = channels[index].copy(lastActivityTimestamp = timestamp)
                dataStorageService.saveChannels(channels.sortedByDescending { it.lastActivityTimestamp })
                Log.d(TAG, "Updated last activity for channel '$channelId' to $timestamp.")
            } else {
                Log.w(TAG, "Cannot update last activity: Channel ID '$channelId' not found.")
            }
        }
    }

    /**
     * Ensures a default channel (e.g., #general) exists.
     * If not, it creates and saves it.
     */
    suspend fun ensureDefaultChannelExists(defaultChannelName: String = "#general") {
        channelsMutex.withLock {
            val channels = dataStorageService.getChannels()
            if (channels.none { it.name.equals(defaultChannelName, ignoreCase = true) }) {
                Log.i(TAG, "Default channel '$defaultChannelName' not found. Creating it.")
                val defaultChannel = ChannelInfo(
                    name = defaultChannelName,
                    isPrivate = false,
                    memberPeerIds = emptyList() // Open channel
                )
                val updatedChannels = channels.toMutableList().apply { add(defaultChannel) }
                dataStorageService.saveChannels(updatedChannels.sortedByDescending { it.lastActivityTimestamp })
            } else {
                Log.d(TAG, "Default channel '$defaultChannelName' already exists.")
            }
        }
    }
}
