package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.Config.NUM_BYTES_IN_SECRET
import org.operatorfoundation.ratchet.models.keys.secure.SecureKey

class Secret(bytes: ByteArray): SecureKey(bytes) {
    init {
        require(bytes.size == NUM_BYTES_IN_SECRET)

        // All-zero check. This shouldn't ever happen, given Bouncy Castle's RFC 7748 protections,
        // but just in case something gets changed up there...

        var result = 0
        bytes.forEachIndexed { i, b ->
            result = result or bytes[i].toInt()
        }
        if (result == 0) {
            throw SecurityException("** All-zero shared secret means something went very wrong **")
        }
    }

}