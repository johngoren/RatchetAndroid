package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.Constants.NUM_BYTES_IN_KEY
import org.operatorfoundation.ratchet.models.keys.secure.SecureKey

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

            val copyOfSharedKeyBytes = sharedSecret.copyBytes()
            require(copyOfSharedKeyBytes.size == NUM_BYTES_IN_KEY) { "ECDH result must be 32 bytes" }
            sharedKey = SharedKey(copyOfSharedKeyBytes)


            return sharedKey ?: throw Exception("Something went wrong")
        }
    }
    
}