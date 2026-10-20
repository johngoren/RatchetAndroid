package org.operatorfoundation.ratchet

import org.junit.Assert
import org.junit.Assert.fail
import org.junit.Test
import org.operatorfoundation.ratchet.TestUtils.mockEphemeralKeypair
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.Decrypt
import org.operatorfoundation.ratchet.utils.Encrypt
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RatchetHardeningTest {

    @Test
    fun `Monotonic counter fails for invalid value`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        val bobRemotePublicKey: EphemeralPublicKey = bobKeypair.publicKeyCopyForTesting

        val alice0 = Ratchet.initRatchetState(
            aliceKeypair,
            bobRemotePublicKey
        )

        val alice1 = Ratchet.ratchetForReceive(alice0, bobRemotePublicKey, 1)
        assertEquals(1, alice1.counterIn)

        // Throws exception if we reuse a counter value
        assertFailsWith<RedoHandshakeException>(
            block = {
                Ratchet.ratchetForReceive(alice1, bobRemotePublicKey, 1)
            }
        )

        assertFailsWith<RedoHandshakeException>(
            block = {
                Ratchet.ratchetForReceive(alice1, bobRemotePublicKey, 0)
            }
        )
    }

    @Test
    fun `Encryption succeeds only when the counter number is valid`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        val aliceRemotePublicKey = aliceKeypair.publicKeyCopyForTesting
        val bobRemotePublicKey = bobKeypair.publicKeyCopyForTesting

        val plaintext = PlaintextMessage(
            PlaintextMessageType.DATA,
            TestUtils.mockPlaintext().toBytes()
        )
        val copyOfOriginalPlaintextBytes = plaintext.bytes.copyOf()

        val alice0 = Ratchet.initRatchetState(
            aliceKeypair,
            bobRemotePublicKey
        )
        val bob0 = Ratchet.initRatchetState(
            bobKeypair,
            aliceRemotePublicKey
        )

        val bob1Result = Ratchet.ratchetForSend(bob0)
        val bobPublicKey = bob1Result.newEphemeralPublicKey
        val bobPublicKeyReused = EphemeralPublicKey(bobPublicKey.copyBytes())

        val encrypted = Encrypt.perform(bob1Result.state.messageKey!!, plaintext)

        val alice1 = Ratchet.ratchetForReceive(alice0, bobPublicKey, 1)
        val decrypted = Decrypt.perform(alice1.messageKey!!, encrypted)
        assertContentEquals(decrypted!!.bytes, copyOfOriginalPlaintextBytes)

        // So far, so good. What if a replay attacker sends Alice the old public key with a new counter number?
        val alice2 = Ratchet.ratchetForReceive(alice1, bobPublicKeyReused, 2)

        // She ratchets and obtains a new message key. But Bob's replay of the public key will fail.
        assertFailsWith<SecurityException>(
            block = {
                Decrypt.perform(alice2.messageKey!!, encrypted)
            }
        )
    }

    // ========== Object lockdown Tests ==========

    @Test
    fun `Key objects cannot be compared or scrutinized`() {
        val key1 = MessageKey(ByteArray(32))
        val key2 = MessageKey(ByteArray(32))

        assert(key1.toString().contains("redacted"))

        try {
            key1.hashCode()
            fail("Should have thrown SecurityException")
        } catch (e: SecurityException) {
            Assert.assertTrue(e.message!!.contains("security"))
        }

        try {
            (key1 == key2)
            fail("Should have thrown SecurityException")
        } catch (e: SecurityException) {
            Assert.assertTrue(e.message!!.contains("security"))
        }
    }
}