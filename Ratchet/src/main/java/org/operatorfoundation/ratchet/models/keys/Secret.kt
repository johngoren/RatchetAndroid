package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.Constants
import org.operatorfoundation.ratchet.models.keys.secure.SecureKey

class Secret(bytes: ByteArray): SecureKey(bytes) {
    init {
        require(bytes.size == Constants.NUM_BYTES_IN_SECRET)
    }
}