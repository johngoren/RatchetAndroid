package org.operatorfoundation.ratchet

/**
 * Represents a shared key derived from ECDH in the double ratchet algorithm.
 */
data class SharedKey(val bytes: ByteArray)
{
    companion object
    {
        /**
         * Create a SharedKey from ECDH result
         */
        fun fromECDH(sharedSecret: ByteArray): SharedKey
        {
            require(sharedSecret.size == 32) { "ECDH result must be 32 bytes" }
            return SharedKey(sharedSecret)
        }
    }

    override fun equals(other: Any?): Boolean
    {
        if (this === other) return true
        if (other !is SharedKey) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}