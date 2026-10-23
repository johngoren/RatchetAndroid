package org.operatorfoundation.ratchet.models

import java.nio.ByteBuffer

/**
 * Plaintext Message
 *
 *
 */
class PlaintextMessage(val type: PlaintextMessageType, val bytes: ByteArray): AutoCloseable
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

        private const val MAX_NUM_BYTES_FOR_REPRESENTING_LENGTH = 3

        fun fromBytes(data: ByteArray): PlaintextMessage
        {
            require(data.size >= 2) { "Data too short to be a valid plaintext message" }

            var offset = 0

            // Read single byte telling us how many bytes to expect for length
            val numBytesRepresentingLength = data[offset].toInt() and 0xFF
            offset += 1

            require(numBytesRepresentingLength in 1..MAX_NUM_BYTES_FOR_REPRESENTING_LENGTH) { "Invalid length size: $numBytesRepresentingLength" }
            require(data.size >= offset + numBytesRepresentingLength) { "Data too short for length field" }

            // Knowing how many bytes to read, we now read the actual length (N bytes, big-endian, unsigned)
            var messageLength = 0
            for (i in 0 until numBytesRepresentingLength)
            {
                messageLength = (messageLength shl 8) or (data[offset].toInt() and 0xFF)
                offset += 1
            }

            require(messageLength >= 1) {
                "Message length must be at least 1"
            }
            require(data.size >= offset + messageLength) { "Data too short for message content" }

            // Read message type (1 byte)
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
            messageLength <= 0xFF -> 1
            messageLength <= 0xFFFF -> 2
            messageLength <= 0xFFFFFF -> 3
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
        throw Exception("Equality comparison has been disabled for security.")
    }

    override fun hashCode(): Int
    {
        throw SecurityException("Hash code has been disabled for security.")
    }

    override fun close() {
        bytes.fill(0)
    }
}