package org.operatorfoundation.ratchet

import org.junit.Assert
import org.junit.Assert.fail
import org.junit.Test
import org.operatorfoundation.ratchet.TestUtils.mockEphemeralKeypair
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RatchetHardeningTest {

    @Test
    fun `AutoCloseable ratchet state can make a copy that survives destruction of original`() {
        val localKeypair = mockEphemeralKeypair()
        var remotePublicKey: EphemeralPublicKey? = null
        val remoteKeypair = mockEphemeralKeypair()
        remoteKeypair.consume { public, private ->
            remotePublicKey = public
        }

        val ratchetState = Ratchet.initRatchetState(
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
    fun `Monotonic counter breaks the shared secret if it does not match`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        val aliceRemotePublicKey = aliceKeypair.publicKeyCopyForTesting
        val bobRemotePublicKey = bobKeypair.publicKeyCopyForTesting

        val alice0 = Ratchet.initRatchetState(
            aliceKeypair,
            bobRemotePublicKey
        )

        val bob1 = Ratchet.initRatchetState(
            bobKeypair,
            aliceRemotePublicKey
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