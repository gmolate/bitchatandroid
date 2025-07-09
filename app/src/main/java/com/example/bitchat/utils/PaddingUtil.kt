package com.example.bitchat.utils

import android.util.Log

/**
 * Utility for PKCS#7 padding and unpadding.
 * PKCS#7 padding is a way to ensure that the data to be encrypted has a length that is a multiple
 * of the cipher's block size.
 */
object PaddingUtil {
    private const val TAG = "PaddingUtil"

    /**
     * Adds PKCS#7 padding to the input data to make its length a multiple of the block size.
     *
     * @param data The input byte array.
     * @param blockSize The block size (in bytes) for the cipher (e.g., 16 for AES).
     * @return The padded byte array.
     * @throws IllegalArgumentException if blockSize is not positive.
     */
    fun pkcs7Pad(data: ByteArray, blockSize: Int): ByteArray {
        if (blockSize <= 0) {
            throw IllegalArgumentException("Block size must be positive.")
        }
        val paddingSize = blockSize - (data.size % blockSize)
        // The padding byte value is the number of padding bytes added.
        val paddingByte = paddingSize.toByte()
        val paddingBytes = ByteArray(paddingSize) { paddingByte }
        return data + paddingBytes
    }

    /**
     * Removes PKCS#7 padding from the input data.
     *
     * @param paddedData The byte array with PKCS#7 padding.
     * @return The original unpadded byte array, or null if padding is invalid or data is empty.
     */
    fun pkcs7Unpad(paddedData: ByteArray): ByteArray? {
        if (paddedData.isEmpty()) {
            Log.w(TAG, "Cannot unpad empty data.")
            return null
        }

        // The last byte indicates the number of padding bytes.
        val paddingSize = paddedData.last().toInt()

        // Validate padding size. It must be between 1 and blockSize (inclusive).
        // Also, it cannot be larger than the data itself.
        if (paddingSize <= 0 || paddingSize > paddedData.size) {
            Log.e(TAG, "Invalid PKCS#7 padding size: $paddingSize for data of length ${paddedData.size}")
            return null // Invalid padding
        }

        // Verify that all padding bytes have the correct value.
        for (i in (paddedData.size - paddingSize) until paddedData.size) {
            if (paddedData[i].toInt() != paddingSize) {
                Log.e(TAG, "Invalid PKCS#7 padding byte encountered at index $i. Expected $paddingSize, got ${paddedData[i]}.")
                return null // Invalid padding
            }
        }

        return paddedData.copyOfRange(0, paddedData.size - paddingSize)
    }
}
