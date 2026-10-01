package org.operatorfoundation.ratchet

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import kotlin.test.assertFailsWith

class PlaintextTests {

    // ========== PlaintextMessageType Tests ==========

    @Test
    fun `PlaintextMessageType has correct byte values`() {
        assertEquals(0x48.toByte(), PlaintextMessageType.HANDSHAKE.value)
        assertEquals(0x52.toByte(), PlaintextMessageType.RATCHET.value)
        assertEquals(0x45.toByte(), PlaintextMessageType.ERROR.value)
        assertEquals(0x43.toByte(), PlaintextMessageType.COMPRESSED_TEXT.value)
        assertEquals(0x55.toByte(), PlaintextMessageType.UNCOMPRESSED_TEXT.value)
        assertEquals(0x44.toByte(), PlaintextMessageType.DATA.value)
    }

    @Test
    fun `PlaintextMessageType fromByte returns correct type`() {
        assertEquals(PlaintextMessageType.HANDSHAKE, PlaintextMessageType.fromByte(0x48))
        assertEquals(PlaintextMessageType.RATCHET, PlaintextMessageType.fromByte(0x52))
        assertEquals(PlaintextMessageType.ERROR, PlaintextMessageType.fromByte(0x45))
        assertEquals(PlaintextMessageType.COMPRESSED_TEXT, PlaintextMessageType.fromByte(0x43))
        assertEquals(PlaintextMessageType.UNCOMPRESSED_TEXT, PlaintextMessageType.fromByte(0x55))
        assertEquals(PlaintextMessageType.DATA, PlaintextMessageType.fromByte(0x44))
    }

    @Test
    fun `PlaintextMessageType fromByte returns null for invalid byte`() {
        assertNull(PlaintextMessageType.fromByte(0x00))
        assertNull(PlaintextMessageType.fromByte(0xFF.toByte()))
    }

    // ========== PlaintextMessage Tests ==========

    @Test
    fun `PlaintextMessage serialization and deserialization round trip`() {
        val originalMessage = PlaintextMessage(
            PlaintextMessageType.DATA,
            "Hello, World!".toByteArray()
        )

        val serialized = originalMessage.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)

        assertEquals(originalMessage.type, deserialized.type)
        assertArrayEquals(originalMessage.bytes, deserialized.bytes)
    }

    @Test
    fun `PlaintextMessage handles empty content`() {
        val message = PlaintextMessage(PlaintextMessageType.ERROR, byteArrayOf())
        val serialized = message.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)

        assertEquals(PlaintextMessageType.ERROR, deserialized.type)
        assertArrayEquals(byteArrayOf(), deserialized.bytes)
    }

    @Test
    fun `PlaintextMessage handles large content`() {
        val largeContent = ByteArray(10000) { it.toByte() }
        val message = PlaintextMessage(PlaintextMessageType.DATA, largeContent)

        val serialized = message.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)

        assertEquals(PlaintextMessageType.DATA, deserialized.type)
        assertArrayEquals(largeContent, deserialized.bytes)
    }

    @Test
    fun `PlaintextMessage will refuse to serialize content that exceeds size limit`() {
        val excessivelyLongContent = ByteArray(5000000)
        val message = PlaintextMessage(PlaintextMessageType.DATA, bytes = excessivelyLongContent)

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                message.toBytes()
            }
        )
    }

    @Test
    fun `PlaintextMessage will refuse to deserialize content beyond its size limits`() {
        val basicContent = ByteArray(100)
        val validWireMessage = PlaintextMessage(PlaintextMessageType.DATA, basicContent).toBytes()

        assert(validWireMessage[0].toInt() == 1)

        val invalidNumOfBytes = 0x05
        val invalidMessage1 = validWireMessage.copyOf().also {
            it[0] = invalidNumOfBytes.toByte()
        }

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(invalidMessage1)
            }
        )

        val zeroValueByte = 0x00
        val invalidMessage2 = validWireMessage.copyOf().also {
            it[0] = zeroValueByte.toByte()
        }

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(invalidMessage2)
            }
        )

        val outOfBoundsByteValue = 0xFF
        val invalidMessage3 = validWireMessage.copyOf().also {
            it[0] = outOfBoundsByteValue.toByte()
        }

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(invalidMessage3)
            }
        )

        validWireMessage.copyOf().also {
            it[0] = outOfBoundsByteValue.toByte()
            val badByteArray = byteArrayOf(outOfBoundsByteValue.toByte())
            val invalidMessage4 = it + badByteArray
            assertFailsWith(
                exceptionClass = IllegalArgumentException::class,
                block = {
                    PlaintextMessage.fromBytes(invalidMessage4)
                }
            )
        }
    }

    @Test
    fun `PlaintextMessage resists zero length attack`() {
        val zeroLengthAttackMessage = byteArrayOf(0x01, 0x00)   // Decoded length 0
        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(zeroLengthAttackMessage)
            }
        )
    }


    @Test
    fun `PlaintextMessage handles UTF-8 text`() {
        val originalText = "Hello 世界 🌍"
        val message = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            originalText.toByteArray(Charsets.UTF_8)
        )

        val serialized = message.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)
        val decodedText = String(deserialized.bytes, Charsets.UTF_8)

        assertEquals(originalText, decodedText)
    }

}