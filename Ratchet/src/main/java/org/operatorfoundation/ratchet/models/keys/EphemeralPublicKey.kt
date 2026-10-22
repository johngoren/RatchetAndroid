package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.Config
import org.operatorfoundation.ratchet.models.keys.secure.SecureKey


/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
class EphemeralPublicKey(bytes: ByteArray, val counter: Int? = null): SecureKey(bytes.copyOf()) {

    init {
        require(bytes.size == Config.NUM_BYTES_IN_KEY)
    }
}
