package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeypair

object TestUtils {

    fun mockKeypair(): SecureKeypair {
        return SecureKeypair(MADH.generateKeypair())
    }

}