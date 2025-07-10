package com.example.bitchat.models

import java.util.UUID

/**
 * Represents information about a communication channel.
 *
 * @property id Unique identifier for the channel (e.g., UUID string or derived from name).
 * @property name The display name of the channel (e.g., "#general", "PrivateChatWithAlice").
 * @property memberPeerIds A list of peer IDs (ephemeral or persistent) that are members of this channel.
 *                         For a 1-to-1 chat, this might contain one other peer's ID.
 * @property isPrivate Indicates if the channel is private (e.g., end-to-end encrypted, possibly password-protected).
 * @property lastActivityTimestamp Timestamp of the last message or significant activity in the channel,
 *                                 used for sorting or indicating freshness.
 * @property unreadCount Number of unread messages in this channel. (Optional, managed by UI/ViewModel logic)
 * @property isJoined Indicates if the current user has actively joined this channel.
 */
data class ChannelInfo(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val memberPeerIds: List<String> = emptyList(),
    val isPrivate: Boolean = false,
    var lastActivityTimestamp: Long = System.currentTimeMillis(),
    var unreadCount: Int = 0, // Default to 0, can be updated by ViewModel/Repository
    var isJoined: Boolean = true // Assume joined if it's in the user's list, can be set to false for discoverable but not joined channels
) {
    // Example: For a 1-to-1 channel, the name might be derived or use the peer's display name.
    // The ID could be a sorted concatenation of user IDs for deterministic 1-to-1 channel IDs.
    companion object {
        fun generateDeterministicIdForDirectChannel(userId1: String, userId2: String): String {
            return listOf(userId1, userId2).sorted().joinToString(separator = "_", prefix = "dm_")
        }
    }
}
