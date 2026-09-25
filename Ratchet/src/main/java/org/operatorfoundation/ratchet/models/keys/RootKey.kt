package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey

/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
class RootKey(bytes: ByteArray): SecureKey(bytes.copyOf())
{
    companion object
    {

        /**
         * Create a RootKey from HKDF result (first 32 bytes)
         */
        fun fromHKDF(hkdfOutput: ByteArray): RootKey
        {
            require(hkdfOutput.size >= 32) { "HKDF output must be at least 32 bytes" }
            return RootKey(hkdfOutput.copyOfRange(0, 32))
        }
    }

}