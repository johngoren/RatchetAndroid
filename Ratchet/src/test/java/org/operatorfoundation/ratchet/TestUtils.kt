package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.Config.NUM_BYTES_IN_SESSION_ID
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair
import java.security.SecureRandom

object TestUtils {

    fun mockEphemeralKeypair(): EphemeralKeypair {
        return EphemeralKeypair(MADH.generateKeypair())
    }

    fun mockRandomSessionId(): ByteArray {
        val random = SecureRandom()
        val bytes = ByteArray(NUM_BYTES_IN_SESSION_ID)
        random.nextBytes(bytes)
        return bytes
    }

    fun mockConstantSessionId(): ByteArray {
        return ByteArray(NUM_BYTES_IN_SESSION_ID)
    }

    fun mockInitialStates(): Pair<RatchetState, RatchetState> {
        val sessionId = mockRandomSessionId()
        val aliceKeys = mockEphemeralKeypair()
        val bobKeys = mockEphemeralKeypair()

        val alice0 = Ratchet.initRatchetState(aliceKeys, bobKeys.publicKeyCopyForTesting, sessionId = sessionId)
        val bob0 = Ratchet.initRatchetState(bobKeys, aliceKeys.publicKeyCopyForTesting, sessionId = sessionId)
        return Pair(alice0, bob0)
    }

    fun mockPlaintext(): PlaintextMessage {
        return PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "'Programs are meant to be read by humans and only incidentally for computers to execute.' -- Don Knuth".toByteArray()
        )
    }

}