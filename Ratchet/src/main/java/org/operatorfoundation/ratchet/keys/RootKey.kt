package org.operatorfoundation.ratchet.keys

/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
class RootKey(bytes: ByteArray): RestrictedKey(bytes)
{
    companion object
    {
        /**
         * Create a RootKey from ECDH result
         */
        fun fromECDH(sharedSecret: ByteArray): RootKey
        {
            require(sharedSecret.size == 32) { "ECDH result must be 32 bytes" }
            return RootKey(sharedSecret)
        }

        /**
         * Create a RootKey from HKDF result (first 32 bytes)
         */
        fun fromHKDF(hkdfOutput: ByteArray): RootKey
        {
            require(hkdfOutput.size >= 32) { "HKDF output must be at least 32 bytes" }
            return RootKey(hkdfOutput.copyOfRange(0, 32))
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