package com.example.bitchat.utils

import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import java.nio.charset.Charset

@Suppress("UnstableApiUsage") // Guava BloomFilter is @Beta
object BloomFilterUtil {

    // Creates a Bloom filter for storing message IDs (UUIDs represented as Strings)
    // Parameters:
    // - expectedInsertions: The number of items you expect to insert.
    // - fpp: Desired false positive probability (e.g., 0.01 for 1%).
    fun createMessageIdFilter(expectedInsertions: Int = 1000, fpp: Double = 0.01): BloomFilter<String> {
        return BloomFilter.create(
            Funnels.stringFunnel(Charset.defaultCharset()), // Or Charsets.UTF_8
            expectedInsertions,
            fpp
        )
    }

    // Adds a message ID to the Bloom filter
    fun addMessageId(filter: BloomFilter<String>, messageId: String) {
        filter.put(messageId)
    }

    // Checks if a message ID might be in the Bloom filter
    // Returns true if the item might be in the set, false if it is definitely not.
    // False positives are possible, but false negatives are not.
    fun mightContainMessageId(filter: BloomFilter<String>, messageId: String): Boolean {
        return filter.mightContain(messageId)
    }
}
