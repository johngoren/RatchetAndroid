package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey

/**
 * Represents a shared key derived from ECDH in the double ratchet algorithm.
 */
class SharedKey(bytes: ByteArray): SecureKey(bytes.copyOf())
{
    companion object
    {
        /**
         * Create a SharedKey from ECDH result
         */
        fun fromECDH(sharedSecret: Secret): SharedKey {
            var sharedKey: SharedKey? = null

            sharedSecret.use { sharedSecret ->
                require(sharedSecret.size == 32) { "ECDH result must be 32 bytes" }
                sharedKey = SharedKey(sharedSecret)
            }

            return sharedKey ?: throw Exception("Something went wrong")
        }
    }
    
}