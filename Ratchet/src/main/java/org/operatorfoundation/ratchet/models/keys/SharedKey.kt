package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.RestrictedKey

/**
 * Represents a shared key derived from ECDH in the double ratchet algorithm.
 */
class SharedKey(bytes: ByteArray): RestrictedKey(bytes.copyOf())
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
    
}