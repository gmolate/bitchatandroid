package com.example.bitchat.utils

import android.util.Log
import net.jpountz.lz4.LZ4Factory
import net.jpountz.lz4.LZ4Compressor
import net.jpountz.lz4.LZ4FastDecompressor
import java.io.ByteArrayOutputStream

object CompressionUtil {
    private const val TAG = "CompressionUtil"
    private val factory = LZ4Factory.fastestInstance() // Or .fastestJavaInstance() for pure Java

    fun compress(data: ByteArray): ByteArray? {
        return try {
            val compressor: LZ4Compressor = factory.fastCompressor()
            // Calculate max compressed length to allocate buffer appropriately
            val maxCompressedLength = compressor.maxCompressedLength(data.size)
            val compressedOutput = ByteArray(maxCompressedLength)
            val compressedLength = compressor.compress(data, 0, data.size, compressedOutput, 0, maxCompressedLength)

            // Trim the output array to the actual compressed size
            val trimmedOutput = ByteArray(compressedLength)
            System.arraycopy(compressedOutput, 0, trimmedOutput, 0, compressedLength)
            Log.d(TAG, "Compressed data from ${data.size} to $compressedLength bytes")
            trimmedOutput
        } catch (e: Exception) {
            Log.e(TAG, "LZ4 Compression error: ${e.message}", e)
            null
        }
    }

    fun decompress(compressedData: ByteArray, originalLength: Int): ByteArray? {
        // The originalLength is crucial for LZ4 decompression with some methods.
        // If the original length is not known, some LZ4 implementations might require
        // the compressed data to be prefixed with its original uncompressed length.
        // The `lz4-java` library's basic decompressor often needs the exact original length.
        return try {
            val decompressor: LZ4FastDecompressor = factory.fastDecompressor()
            val restored = ByteArray(originalLength)
            val compressedLength = decompressor.decompress(compressedData, 0, restored, 0, originalLength)

            if (compressedLength != compressedData.size) {
                 // This might indicate an issue if not all compressed bytes were consumed,
                 // or if the originalLength was incorrect.
                 Log.w(TAG, "LZ4 Decompression: Processed $compressedLength bytes of ${compressedData.size} compressed bytes. Original length target: $originalLength")
            }
            Log.d(TAG, "Decompressed data from ${compressedData.size} to $originalLength bytes")
            restored
        } catch (e: Exception) {
            Log.e(TAG, "LZ4 Decompression error: ${e.message}", e)
            null
        }
    }

     // Alternative decompression if original length isn't stored separately but part of the stream
    // This depends on how data was compressed and stored.
    // For example, if using LZ4FrameOutputStream, it handles this.
    // The basic compressor/decompressor used above require known original length.
    // This is a placeholder for a more robust method if needed.
    fun decompressUnknownOriginalLength(compressedData: ByteArray): ByteArray? {
        // This typically requires a format that includes the original size,
        // or using a decompressor that can handle streams without prior knowledge of size.
        // LZ4Factory.safeDecompressor or LZ4FrameInputStream might be alternatives.
        Log.w(TAG, "decompressUnknownOriginalLength is a placeholder and might not work correctly without stream format knowledge.")
        // For now, try with a large buffer, this is INEFFICIENT and potentially error-prone.
        return try {
            val decompressor: LZ4FastDecompressor = factory.fastDecompressor()
            // Guess a large enough buffer, this is not ideal.
            val outputBuffer = ByteArrayOutputStream()
            // This specific decompress method might not be suitable here without knowing the output size.
            // A streaming decompressor or a format that includes size is better.
            // For now, let's assume we can try to decompress into a sufficiently large buffer.
            // This is a conceptual example and might need a different LZ4 API for unknown output size.
            val tempRestored = ByteArray(compressedData.size * 5) // Arbitrary guess for expansion
            val decompressedSize = decompressor.decompress(compressedData, tempRestored)
            outputBuffer.write(tempRestored, 0, decompressedSize)
            outputBuffer.toByteArray()
        } catch (e: Exception) {
            Log.e(TAG, "LZ4 Decompression (unknown original length) error: ${e.message}", e)
            null
        }
    }
}
