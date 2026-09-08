package org.operatorfoundation.ratchet

import java.nio.ByteBuffer

class PlaintextMessage(val type: PlaintextMessageType, val bytes: ByteArray)
{
    companion object
    {
        /**
         * Deserialize a PlaintextMessage from its wire format.
         *
         * Format:
         * - 1 byte: size of length (N)
         * - N bytes: length in big-endian
         * - 1 byte: message type
         * - remaining: message content
         *
         * @param data The serialized message data
         * @return The deserialized PlaintextMessage
         * @throws IllegalArgumentException if the data is invalid
         */
        fun fromBytes(data: ByteArray): PlaintextMessage
        {
            require(data.size >= 2) { "Data too short to be a valid plaintext message" }

            var offset = 0

            // Read length size (1 byte)
            val lengthSize = data[offset].toInt() and 0xFF
            offset += 1

            require(lengthSize > 0 && lengthSize <= 8) { "Invalid length size: $lengthSize" }
            require(data.size >= offset + lengthSize) { "Data too short for length field" }

            // Read length (N bytes, big-endian)
            var messageLength = 0L
            for (i in 0 until lengthSize)
            {
                messageLength = (messageLength shl 8) or (data[offset].toLong() and 0xFF)
                offset += 1
            }

            require(data.size >= offset + messageLength) { "Data too short for message content" }

            // Read type (1 byte)
            val typeByte = data[offset]
            offset += 1

            val type = PlaintextMessageType.fromByte(typeByte)
                ?: throw IllegalArgumentException("Unknown message type: 0x${typeByte.toString(16)}")

            // Read message content (remaining bytes)
            val contentLength = messageLength.toInt() - 1 // Subtract 1 for the type byte
            require(contentLength >= 0) { "Invalid message length" }

            val content = data.copyOfRange(offset, offset + contentLength)

            return PlaintextMessage(type, content)
        }
    }

    /**
     * Serialize this PlaintextMessage to its wire format.
     *
     * Format:
     * - 1 byte: size of length (N)
     * - N bytes: length in big-endian
     * - 1 byte: message type
     * - remaining: message content
     *
     * The length includes the type byte and content bytes.
     *
     * @return The serialized message
     */
    fun toBytes(): ByteArray
    {
        // Calculate total message length (type byte + content)
        val messageLength = 1L + bytes.size

        // Calculate how many bytes we need for the length
        // Drop leading zeros as per spec
        val lengthSize = when
        {
            messageLength <= 0xFF -> 1
            messageLength <= 0xFFFF -> 2
            messageLength <= 0xFFFFFF -> 3
            messageLength <= 0xFFFFFFFF -> 4
            messageLength <= 0xFFFFFFFFFF -> 5
            messageLength <= 0xFFFFFFFFFFFF -> 6
            messageLength <= 0xFFFFFFFFFFFFFF -> 7
            else -> 8
        }

        // Allocate buffer
        val totalSize = 1 + lengthSize + 1 + bytes.size
        val buffer = ByteBuffer.allocate(totalSize)

        // Write length size (1 byte)
        buffer.put(lengthSize.toByte())

        // Write length in big-endian, dropping leading zeros
        for (i in (lengthSize - 1) downTo 0)
        {
            val byteValue = (messageLength shr (i * 8)) and 0xFF
            buffer.put(byteValue.toByte())
        }

        // Write type (1 byte)
        buffer.put(type.value)

        // Write content
        buffer.put(bytes)

        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PlaintextMessage) return false
        if (type != other.type) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        // Use prime multiplier for better hash distribution when combining fields
        val HASH_PRIME = 31
        var result = type.hashCode()
        result = HASH_PRIME * result + bytes.contentHashCode()
        return result
    }
}