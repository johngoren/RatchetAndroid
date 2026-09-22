package org.operatorfoundation.ratchet.models

/**
 * Enumeration of plaintext message types in the Ratchet protocol.
 * Each type corresponds to a specific byte value used in the message format.
 */
enum class PlaintextMessageType(val value: Byte)
{
    // Metadata Messages

    /** Handshake message - exchange long-term public keys */
    HANDSHAKE(0x48), // 'H'

    /** Ratchet message - new ephemeral key material */
    RATCHET(0x52), // 'R'

    /** Error message */
    ERROR(0x45), // 'E'

    // Content Messages

    /** Compressed UTF-8 text */
    COMPRESSED_TEXT(0x43), // 'C'

    /** Uncompressed UTF-8 text */
    UNCOMPRESSED_TEXT(0x55), // 'U'

    /** Binary data */
    DATA(0x44); // 'D'

    companion object {
        /**
         * Get PlaintextMessageType from its byte value.
         *
         * @param value The byte value to look up
         * @return The corresponding PlaintextMessageType, or null if not found
         */
        fun fromByte(value: Byte): PlaintextMessageType?
        {
            return values().firstOrNull { it.value == value }
        }
    }
}