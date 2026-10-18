package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair

object TestUtils {

    fun mockEphemeralKeypair(): EphemeralKeypair {
        return EphemeralKeypair(MADH.generateKeypair())
    }

    fun mockPlaintext(): PlaintextMessage {
        return PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "Hello, World!".toByteArray()
        )

    }

}