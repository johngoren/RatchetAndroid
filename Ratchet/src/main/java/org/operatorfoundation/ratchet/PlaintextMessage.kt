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

        private const val MAX_LENGTH_SIZE_BYTES = 3

        fun fromBytes(data: ByteArray): PlaintextMessage
        {
            require(data.size >= 2) { "Data too short to be a valid plaintext message" }

            var offset = 0

            // Read number of bytes to expect in length (1 byte)
            val numBytesInLength = data[offset].toInt() and 0xFF
            offset += 1

            require(numBytesInLength in 1..MAX_LENGTH_SIZE_BYTES) { "Invalid length size: $numBytesInLength" }
            require(data.size >= offset + numBytesInLength) { "Data too short for length field" }

            // Read actual length (N bytes, big-endian, signed)
            var messageLength = 0
            for (i in 0 until numBytesInLength)
            {
                messageLength = (messageLength shl 8) or (data[offset].toInt() and 0xFF)
                offset += 1
            }

            val maxAllowedLength = when(numBytesInLength) {
                1 -> 0x7F
                2 -> 0x7FFF
                3 -> 0x7FFFF
                else -> 0
            }

            require(messageLength in 1..maxAllowedLength) {
                "Length $messageLength exceeds maximum signed value for $numBytesInLength byte(s)"
            }

            require(data.size >= offset + messageLength) { "Data too short for message content" }

            // Read type (1 byte)
            val typeByte = data[offset]
            offset += 1

            val type = PlaintextMessageType.fromByte(typeByte)
                ?: throw IllegalArgumentException("Unknown message type: 0x${typeByte.toString(16)}")

            // Read message content (remaining bytes)
            val contentLength = messageLength - 1 // Subtract 1 for the type byte
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
        val messageLength = 1 + bytes.size

        // Calculate how many bytes we need for the length
        // Drop leading zeros as per spec
        val numBytesForLength = when
        {
            messageLength <= 0x7F -> 1
            messageLength <= 0x7FFF -> 2
            messageLength <= 0x7FFFF -> 3
            else -> throw IllegalArgumentException("Plaintext message length exceeds maximum")
        }

        // Allocate buffer
        val totalSize = 1 + numBytesForLength + 1 + bytes.size
        val buffer = ByteBuffer.allocate(totalSize)

        // Write length size (1 byte)
        buffer.put(numBytesForLength.toByte())

        // Write length in big-endian, dropping leading zeros
        for (i in (numBytesForLength - 1) downTo 0)
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