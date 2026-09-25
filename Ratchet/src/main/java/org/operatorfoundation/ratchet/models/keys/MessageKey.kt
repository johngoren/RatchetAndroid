package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey

/**
 * Represents a message key used to encrypt/decrypt individual messages.
 * Derived from the chain key in the double ratchet algorithm.
 */
class MessageKey(bytes: ByteArray): SecureKey(bytes.copyOf())
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

}
