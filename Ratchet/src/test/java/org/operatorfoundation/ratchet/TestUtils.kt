package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeyPair

object TestUtils {

    fun mockKeypair(): SecureKeyPair {
        return SecureKeyPair(MADH.generateKeypair())
    }

    fun mockPlaintext(): PlaintextMessage {
        return PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "Hello, World!".toByteArray()
        )

    }

}