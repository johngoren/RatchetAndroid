package org.operatorfoundation.ratchet

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.TestUtils.mockEphemeralKeypair
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.Decrypt
import org.operatorfoundation.ratchet.utils.Encrypt
import java.security.PublicKey
import kotlin.test.assertTrue

class RatchetHardeningTest {

    // TODO: Test that everything is destroyed after use and that nothing remains

    @Test
    fun `Autoclosable ratchet state can make a copy that survives destruction of original`() {
        val localKeypair = mockEphemeralKeypair()
        var remotePublicKey: EphemeralPublicKey? = null
        val remoteKeypair = mockEphemeralKeypair()
        remoteKeypair.consume { public, private ->
            remotePublicKey = public
        }

        val ratchetState = DoubleRatchet.initRatchetState(
            localKeypair,
            remotePublicKey!!
        )

        var copyOfRatchetState: RatchetState? = null
        var copyOfRootKey: ByteArray? = null

        ratchetState.use { originalRatchetState ->
            copyOfRatchetState = RatchetState(originalRatchetState)
            copyOfRootKey = originalRatchetState.rootKey.bytesForTesting
        }
        ratchetState.close()

        val zeroizedBytes = ByteArray(32).fill(0)

        assertTrue(copyOfRatchetState != null)
        assertTrue(copyOfRootKey?.first()!!.equals(zeroizedBytes))
        assertTrue(copyOfRatchetState?.rootKey?.bytesForTesting != null)
    }


    @Test
    fun `Reuse of ECDH public key is thwarted by counter`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var firstBobEphemeralPublicKey: EphemeralPublicKey? = null
        var reusedBobPublicKey: EphemeralPublicKey? = null

        var copyOfAlicePublicKey: EphemeralPublicKey? = null
        var copyOfBobPublicKey: EphemeralPublicKey? = null

        aliceKeypair.consume { public, private ->
            copyOfAlicePublicKey = public
        }

        bobKeypair.consume { public, private ->
            copyOfBobPublicKey = public
        }

        val initialStateAlice = DoubleRatchet.initRatchetState(
            aliceKeypair,
            copyOfBobPublicKey!!
        )

        val initialStateBob = DoubleRatchet.initRatchetState(
            bobKeypair,
            copyOfAlicePublicKey!!
        )

        // Bob ratchets and sends the first message
        val bobRatchetsResult = DoubleRatchet.ratchetForSend(initialStateBob)
        val bobState1 = bobRatchetsResult.state
        firstBobEphemeralPublicKey = bobRatchetsResult.newEphemeralPublicKey

        val originalMessage = TestUtils.mockPlaintext()
        var messageKeyBob1: MessageKey? = null
        bobState1.use { bobState1 ->
            messageKeyBob1 = bobState1.messageKey
        }
        val ciphertext1 = Encrypt.perform(messageKeyBob1!!, originalMessage)

        // This ciphertext is then sent over to the wire. Alice receives and decrypts it OK. So far so good

        val aliceState1 = DoubleRatchet.ratchetForReceive(initialStateAlice, firstBobEphemeralPublicKey)
        var messageKeyAlice1: MessageKey? = null
        aliceState1.use { alice1StatePeek ->
            messageKeyAlice1 = alice1StatePeek.messageKey
        }

        val aliceSuccessfullyDecrypts = Decrypt.perform(messageKeyAlice1!!, ciphertext1)
        assertArrayEquals(originalMessage.bytes, aliceSuccessfullyDecrypts!!.bytes)

        reusedBobPublicKey = firstBobEphemeralPublicKey

        val bobState2 = DoubleRatchet.ratchetForSend(bobState1).state
        var messageKeyBob2: MessageKey? = null

        bobState2.use { statePeek ->
            messageKeyBob2 = statePeek.messageKey
        }
        val ciphertext2 = Encrypt.perform(messageKeyBob2!!, originalMessage)

        // Alice receives this but with the old public key.

        val aliceState2 = DoubleRatchet.ratchetForReceive(aliceState1, reusedBobPublicKey)
        var messageKeyAlice2: MessageKey? = null
        aliceState2.use { statePeek ->
            messageKeyAlice2 = statePeek.messageKey
        }

        try {
            val aliceCantDecrypt = Decrypt.perform(messageKeyAlice2!!, ciphertext2)
        }
        catch(e: Exception) {
            // TODO: Test for failure here
        }

    }
}