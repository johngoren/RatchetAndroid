package org.operatorfoundation.ratchet.keys

/**
 * Represents the chain key in the double ratchet algorithm.
 * The chain key is used to derive message keys.
 */
class ChainKey(bytes: ByteArray): RestrictedKey(bytes)
{
    companion object
    {
        /**
         * Create a ChainKey from HKDF result (second 32 bytes)
         */
        fun fromHKDF(hkdfOutput: ByteArray): ChainKey
        {
            require(hkdfOutput.size >= 64) { "HKDF output must be at least 64 bytes" }
            return ChainKey(hkdfOutput.copyOfRange(32, 64))
        }

        /**
         * Create a ChainKey from HMAC result
         */
        fun fromHMAC(hmacOutput: ByteArray): ChainKey
        {
            require(hmacOutput.size == 32) { "HMAC output must be 32 bytes" }
            return ChainKey(hmacOutput)
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