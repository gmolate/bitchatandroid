package com.example.bitchat.utils

import android.util.Log

/**
 * Utility for PKCS#7 padding and unpadding.
 * PKCS#7 padding is a scheme to ensure that data to be encrypted has a length
 * that is a multiple of the cipher's block size. The value of each padding byte
 * is the number of padding bytes added.
 */
object PaddingUtil {
    private const val TAG = "PaddingUtil"

    /**
     * Adds PKCS#7 padding to the input data.
     *
     * @param data The input byte array.
     * @param blockSize The block size (in bytes) for which padding is required (e.g., 16 for AES).
     * @return The padded byte array.
     * @throws IllegalArgumentException if blockSize is not positive.
     */
    fun pkcs7Pad(data: ByteArray, blockSize: Int): ByteArray {
        if (blockSize <= 0) {
            Log.e(TAG, "Block size must be positive. Received: $blockSize")
            throw IllegalArgumentException("Block size must be positive.")
        }
        // Calculate the number of padding bytes needed.
        // If data.size is already a multiple of blockSize, a full block of padding is added.
        val paddingSize = blockSize - (data.size % blockSize)
        val paddingByte = paddingSize.toByte()
        val paddingBytes = ByteArray(paddingSize) { paddingByte }

        val result = ByteArray(data.size + paddingSize)
        System.arraycopy(data, 0, result, 0, data.size)
        System.arraycopy(paddingBytes, 0, result, data.size, paddingSize)

        // Log.d(TAG, "Padded data. Original size: ${data.size}, Block size: $blockSize, Padding size: $paddingSize, Padded size: ${result.size}")
        return result
    }

    /**
     * Removes PKCS#7 padding from the input data.
     *
     * @param paddedData The byte array with PKCS#7 padding.
     * @return The original unpadded byte array.
     * @throws IllegalArgumentException if padding is invalid (e.g., padding size indicates a value
     *         larger than available data, or padding bytes are inconsistent).
     *         Returns null if paddedData is empty.
     */
    fun pkcs7Unpad(paddedData: ByteArray): ByteArray? {
        if (paddedData.isEmpty()) {
            Log.w(TAG, "Cannot unpad empty data array.")
            return null // Or throw, depending on desired error handling
        }

        // The value of the last byte is the number of padding bytes.
        val paddingSize = paddedData.last().toInt() and 0xFF // Ensure positive value if byte > 127

        // Validate padding size.
        // 1. It must be positive.
        // 2. It cannot be larger than the block size (implicitly, also not larger than paddedData.size).
        //    If we don't know the original block size here, we can only check against paddedData.size.
        //    A common block size is 16 (AES), so paddingSize won't exceed that.
        if (paddingSize <= 0 || paddingSize > paddedData.size) {
            Log.e(TAG, "Invalid PKCS#7 padding size: $paddingSize for data of length ${paddedData.size}.")
            throw IllegalArgumentException("Invalid PKCS#7 padding size.")
        }

        // Verify that all padding bytes have the correct value (equal to paddingSize).
        for (i in (paddedData.size - paddingSize) until paddedData.size) {
            if ((paddedData[i].toInt() and 0xFF) != paddingSize) {
                Log.e(TAG, "Invalid PKCS#7 padding byte encountered at index $i. Expected $paddingSize, got ${paddedData[i]}.")
                throw IllegalArgumentException("Invalid PKCS#7 padding bytes.")
            }
        }

        val unpaddedSize = paddedData.size - paddingSize
        val result = ByteArray(unpaddedSize)
        System.arraycopy(paddedData, 0, result, 0, unpaddedSize)

        // Log.d(TAG, "Unpadded data. Padded size: ${paddedData.size}, Padding size: $paddingSize, Original size: ${result.size}")
        return result
    }
}
