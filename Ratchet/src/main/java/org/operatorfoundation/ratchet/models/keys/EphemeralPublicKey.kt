package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.Config
import org.operatorfoundation.ratchet.Config.LIFESPAN_EPHEMERAL_KEY_HOURS
import org.operatorfoundation.ratchet.models.keys.secure.SecureKey


/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
class EphemeralPublicKey(bytes: ByteArray): SecureKey(bytes.copyOf(), lifespanHours = LIFESPAN_EPHEMERAL_KEY_HOURS) {

    init {
        require(bytes.size == Config.NUM_BYTES_IN_KEY)
    }
}
