package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeyPair

object TestUtils {

    fun mockKeypair(): SecureKeyPair {
        return SecureKeyPair(MADH.generateKeypair())
    }

}