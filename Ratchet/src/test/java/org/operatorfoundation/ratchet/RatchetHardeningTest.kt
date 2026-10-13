package org.operatorfoundation.ratchet

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.TestUtils.mockKeypair
import org.operatorfoundation.ratchet.models.keys.MessageKey

class RatchetHardeningTest {

    @Test
    fun `Reuse of ECDH public key is thwarted by counter`() {
        val aliceKeypair = mockKeypair()
        val bobKeypair = mockKeypair()

        var firstBobEphemeralPublicKey: Curve25519PublicKey? = null
        var reusedBobPublicKey: Curve25519PublicKey? = null

        val initialStateAlice = DoubleRatchet.initRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val initialStateBob = DoubleRatchet.initRatchetState(
            bobKeypair,
            aliceKeypair.publicKey
        )

        // Bob ratchets and sends the first message
        val bobRatchetsResult = DoubleRatchet.ratchetForSend(initialStateBob)
        val bobState1 = bobRatchetsResult.state
        firstBobEphemeralPublicKey = bobRatchetsResult.outgoingEphemeralPublicKey

        val originalMessage = TestUtils.mockPlaintext()
        var messageKeyBob1: MessageKey? = null
        bobState1.use { statePeek ->
            messageKeyBob1 = statePeek.messageKey
        }
        val ciphertext1 = DoubleRatchet.encrypt(messageKeyBob1!!, originalMessage)

        // This ciphertext is then sent over to the wire. Alice receives and decrypts it OK. So far so good

        val aliceState1 = DoubleRatchet.ratchetForReceive(initialStateAlice, firstBobEphemeralPublicKey)
        var messageKeyAlice1: MessageKey? = null
        aliceState1.use { alice1StatePeek ->
            messageKeyAlice1 = alice1StatePeek.messageKey
        }

        val aliceSuccessfullyDecrypts = DoubleRatchet.decrypt(messageKeyAlice1!!, ciphertext1)
        assertArrayEquals(originalMessage.bytes, aliceSuccessfullyDecrypts!!.bytes)

        reusedBobPublicKey = firstBobEphemeralPublicKey

        val bobState2 = DoubleRatchet.ratchetForSend(bobState1).state
        var messageKeyBob2: MessageKey? = null

        bobState2.use { statePeek ->
            messageKeyBob2 = statePeek.messageKey
        }
        val ciphertext2 = DoubleRatchet.encrypt(messageKeyBob2!!, originalMessage)

        // Alice receives this but with the old public key.

        val aliceState2 = DoubleRatchet.ratchetForReceive(aliceState1, reusedBobPublicKey)
        var messageKeyAlice2: MessageKey? = null
        aliceState2.use { statePeek ->
            messageKeyAlice2 = statePeek.messageKey
        }

        try {
            val aliceCantDecrypt = DoubleRatchet.decrypt(messageKeyAlice2!!, ciphertext2)
        }
        catch(e: Exception) {
            // TODO: Test for failure here
        }

    }
}