package org.operatorfoundation.ratchet.keys

/**
 * Represents a message key used to encrypt/decrypt individual messages.
 * Derived from the chain key in the double ratchet algorithm.
 */
class MessageKey(bytes: ByteArray): RestrictedKey(bytes)
{
    companion object
    {
        /**
         * Create a MessageKey from HMAC result
         */
        fun fromHMAC(hmacOutput: ByteArray): MessageKey
        {
            require(hmacOutput.size == 32) { "HMAC output must be 32 bytes" }
            return MessageKey(hmacOutput)
        }
    }

    override fun equals(other: Any?): Boolean
    {
        return false // No-op
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}
