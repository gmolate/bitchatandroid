package com.example.bitchat.utils

import android.util.Log
import net.jpountz.lz4.LZ4Factory
import net.jpountz.lz4.LZ4Compressor
import net.jpountz.lz4.LZ4FastDecompressor
import java.io.ByteArrayOutputStream

object CompressionUtil {
    private const val TAG = "BitChatCompress" // Consistent TAG prefix
    private val factory = LZ4Factory.fastestInstance()

    fun compress(data: ByteArray): ByteArray? {
        if (data.isEmpty()) {
            Log.d(TAG, "Input data for compression is empty. Returning empty array.")
            return ByteArray(0)
        }
        Log.d(TAG, "Attempting to compress ${data.size} bytes.")
        return try {
            val compressor: LZ4Compressor = factory.fastCompressor()
            val maxCompressedLength = compressor.maxCompressedLength(data.size)
            val compressedOutput = ByteArray(maxCompressedLength)
            val compressedLength = compressor.compress(data, 0, data.size, compressedOutput, 0, maxCompressedLength)

            val trimmedOutput = compressedOutput.copyOf(compressedLength)
            Log.i(TAG, "LZ4 Compression successful: ${data.size}B -> ${trimmedOutput.size}B.")
            trimmedOutput
        } catch (e: Exception) {
            Log.e(TAG, "LZ4 Compression error for data size ${data.size}B: ${e.message}", e)
            null
        }
    }

    fun decompress(compressedData: ByteArray, originalLength: Int): ByteArray? {
        if (compressedData.isEmpty() && originalLength == 0) {
            Log.d(TAG, "Input compressed data is empty and original length is 0. Returning empty array.")
            return ByteArray(0)
        }
        if (compressedData.isEmpty()) {
            Log.w(TAG, "Input compressed data is empty, but originalLength is $originalLength. Decompression will likely fail or return incorrect data.")
            // Depending on lz4-java behavior, it might throw or return empty/garbage.
            // It's safer to return null or expect an error if originalLength > 0.
        }
        if (originalLength <= 0) {
            Log.e(TAG, "LZ4 Decompression error: Original length must be positive. Was $originalLength for compressed size ${compressedData.size}B.")
            return null // LZ4 requires positive originalLength for this decompressor
        }
        Log.d(TAG, "Attempting to decompress ${compressedData.size} bytes to original length $originalLength bytes.")
        return try {
            val decompressor: LZ4FastDecompressor = factory.fastDecompressor()
            val restored = ByteArray(originalLength)
            // The decompress method returns the number of bytes read from the compressedData buffer.
            // It can throw an exception if originalLength is too small for the decompressed data.
            val bytesReadFromCompressed = decompressor.decompress(compressedData, 0, restored, 0, originalLength)

            // It's possible bytesReadFromCompressed < compressedData.size if there's extra data or padding in compressedData
            // that wasn't part of the actual LZ4 stream for the given originalLength.
            // This is not necessarily an error if the restored data is correct.
            Log.i(TAG, "LZ4 Decompression successful: ${compressedData.size}B (read $bytesReadFromCompressed B) -> ${restored.size}B (target $originalLength B).")
            restored
        } catch (e: Exception) { // Catches LZ4Exception, ArrayIndexOutOfBoundsException, etc.
            Log.e(TAG, "LZ4 Decompression error for compressed size ${compressedData.size}B to original length ${originalLength}B: ${e.message}", e)
            null
        }
    }
    // Removed decompressUnknownOriginalLength as it's unreliable without specific stream format knowledge
    // and our protocol aims to provide originalLength when compression is used.
}
