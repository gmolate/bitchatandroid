package com.example.bitchat.utils

import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.StandardCharsets

class CompressionUtilTest {

    @Test
    fun compress_decompress_successful() {
        val originalString = "Hello BitChat! This is a test string for LZ4 compression and decompression. Repeat it. Repeat it. Repeat it for better compression."
        val originalData = originalString.toByteArray(StandardCharsets.UTF_8)

        val compressedData = CompressionUtil.compress(originalData)
        assertNotNull("Compressed data should not be null", compressedData)
        assertTrue("Compressed data should generally be smaller for repetitive text", compressedData!!.size < originalData.size)

        val decompressedData = CompressionUtil.decompress(compressedData, originalData.size)
        assertNotNull("Decompressed data should not be null", decompressedData)
        assertArrayEquals("Decompressed data should match original data", originalData, decompressedData)

        val decompressedString = decompressedData?.toString(StandardCharsets.UTF_8)
        assertEquals("Decompressed string should match original string", originalString, decompressedString)
    }

    @Test
    fun compress_emptyData_returnsEmptyOrNull() {
        val originalData = ByteArray(0)
        val compressedData = CompressionUtil.compress(originalData)
        // LZ4 might return non-null empty or very small representation for empty input
        assertNotNull(compressedData)
        // For empty input, it might not compress or result in a very small fixed-size output (header/empty block)
        //assertTrue(compressedData!!.isEmpty() || compressedData.size < 10) // Check specific behavior if known

        if (compressedData != null) {
            val decompressedData = CompressionUtil.decompress(compressedData, originalData.size)
            assertNotNull(decompressedData)
            assertArrayEquals(originalData, decompressedData)
        }
    }

    @Test
    fun decompress_invalidData_returnsNullOrThrows() {
        // This test's outcome depends on how robust the LZ4 decompressor is to malformed input.
        // It might return null, throw an exception, or return incorrect data.
        // We expect our wrapper to catch exceptions and return null.
        val invalidCompressedData = "This is not LZ4 data".toByteArray()
        val decompressedData = CompressionUtil.decompress(invalidCompressedData, 100) // Assume original size 100
        assertNull("Decompression of invalid data should ideally return null", decompressedData)
    }

    @Test
    fun decompress_incorrectOriginalLength_mayFailOrReturnPartial() {
        val originalString = "Short string"
        val originalData = originalString.toByteArray(StandardCharsets.UTF_8)
        val compressedData = CompressionUtil.compress(originalData)
        assertNotNull(compressedData)

        // Test with too small original length
        var decompressedData = CompressionUtil.decompress(compressedData!!, originalData.size - 1)
        // Behavior here is LZ4 library dependent. It might throw, return null, or partial data.
        // Our wrapper should ideally return null if the decompression process itself signals an error.
        // If it returns partial data, this assertion might fail or need adjustment.
        if (decompressedData != null) {
             assertNotEquals("Decompressed data with too small length should not match original", originalString, decompressedData.toString(StandardCharsets.UTF_8))
        }


        // Test with too large original length
        decompressedData = CompressionUtil.decompress(compressedData, originalData.size + 10)
        // LZ4 might fill the extra space with zeros or throw.
        // If it returns the correct data within a larger buffer, this needs specific checks.
        // For now, we primarily care that it doesn't crash and ideally returns the correct prefix.
        if (decompressedData != null) {
            val decompressedString = decompressedData.copyOfRange(0, originalData.size).toString(StandardCharsets.UTF_8)
            assertEquals("Decompressed prefix should match original string when target buffer is larger", originalString, decompressedString)
        }
    }

    // Test with data that doesn't compress well
    @Test
    fun compress_randomData_sizeMayNotDecreaseSignificantly() {
        val randomData = ByteArray(1024)
        Random().nextBytes(randomData)

        val compressedData = CompressionUtil.compress(randomData)
        assertNotNull(compressedData)
        // For random data, compression might not reduce size much, or even increase it slightly due to overhead.
        // Log.d("CompressionTest", "Random data: Original size ${randomData.size}, Compressed size ${compressedData!!.size}")

        val decompressedData = CompressionUtil.decompress(compressedData!!, randomData.size)
        assertNotNull(decompressedData)
        assertArrayEquals(randomData, decompressedData)
    }
}
