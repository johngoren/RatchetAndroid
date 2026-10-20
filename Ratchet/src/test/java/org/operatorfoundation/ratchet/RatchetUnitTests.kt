package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.ratchet.TestUtils.mockEphemeralKeypair
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.Decrypt
import org.operatorfoundation.ratchet.utils.Encrypt


class RatchetUnitTests {

    // ========== RatchetState Tests ==========

    @Test
    fun `newRatchetState creates initial state with initial ephemeral keys only`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()
        val alicePublicKey = aliceKeypair.publicKeyCopyForTesting
        val bobPublicKey = bobKeypair.publicKeyCopyForTesting

        val newRatchetState = Ratchet.initRatchetState(
            aliceKeypair,
            bobPublicKey
        )

        newRatchetState.use {

            // Initial state should have ephemeral keys and root key
            assertNotNull(it.rootKey)
            assertEquals(32, it.rootKey.bytesForTesting.size)
            assertArrayEquals(
                alicePublicKey.bytesForTesting,
                it.localEphemeralKeypair.publicKeyBytesForTesting
            )

            assertArrayEquals(
                aliceKeypair.privateKeyBytesForTesting,
                it.localEphemeralKeypair.privateKeyBytesForTesting
            )

            assertArrayEquals(
                bobKeypair.publicKeyBytesForTesting,
                it.remoteEphemeralPublicKey.bytesForTesting
            )

            // Ephemeral state should be default
            assertEquals(0, it.messageNumber)
            assertNull(it.chainKey)
            assertNull(it.sharedKey)
            assertNull(it.messageKey)
            assertTrue(it.localEphemeralKeypair.privateKeyBytesForTesting.contentEquals(aliceKeypair.privateKeyBytesForTesting))
            assertTrue(it.remoteEphemeralPublicKey.bytesForTesting.contentEquals(bobKeypair.publicKeyBytesForTesting))
        }
    }

    @Test
    fun `ratchetForSend generates ephemeral keys and derives chain`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()
        val bobPublicKey = bobKeypair.publicKeyCopyForTesting

        val initialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKey)

        initialState.use { state0 ->

            val copyOfInitialRootKey = state0.rootKey.bytesForTesting

            // Perform first ratchet with new key
            val result = Ratchet.ratchetForSend(initialState)
            result.state.use { state1 ->

                // Should now have all ephemeral state
                assertNotNull(state1.chainKey)
                assertNotNull(state1.sharedKey)
                assertNotNull(state1.messageKey)
                assertNotNull(result.newEphemeralPublicKey)

                // Message number should increment
                assertEquals(1, state1.messageNumber)

                // Root key should be different from initial
                assertFalse(copyOfInitialRootKey.contentEquals(state1.rootKey.bytesForTesting))

                // All keys should be 32 bytes
                assertEquals(32, state1.chainKey!!.bytesForTesting.size)
                assertEquals(32, state1.sharedKey!!.bytesForTesting.size)
                assertEquals(32, state1.messageKey!!.bytesForTesting.size)
                assertEquals(32, result.newEphemeralPublicKey.bytesForTesting.size)
            }
        }
    }

    @Test
    fun `ratchetForReceive generates state from sender ephemeral key`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var copyOfRootKeyInitial: ByteArray? = null

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->
            val initialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKey)

            initialState.use {

                copyOfRootKeyInitial = it.rootKey.bytesForTesting.copyOf()

                // Bob sends his ephemeral key
                val bobEphemeralKeypair = mockEphemeralKeypair()

                bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                    Ratchet.ratchetForReceive(it, bobPublicKey)
                        .use { ratchetedState ->

                            assertNotNull(ratchetedState.chainKey)
                            assertNotNull(ratchetedState.sharedKey)
                            assertNotNull(ratchetedState.messageKey)
                            assertNotNull(ratchetedState.remoteEphemeralPublicKey)

                            // Should now have all ephemeral state

                            // Message number should increment

                            assertEquals(1, ratchetedState.messageNumber)

                            // Root key should be different from initial
                            assertFalse(copyOfRootKeyInitial.contentEquals(ratchetedState.rootKey.bytesForTesting))

                            // All keys should be 32 bytes
                            assertEquals(32, ratchetedState.chainKey!!.bytesForTesting.size)
                            assertEquals(32, ratchetedState.sharedKey!!.bytesForTesting.size)
                            assertEquals(32, ratchetedState.messageKey!!.bytesForTesting.size)

                        }
                }
            }
        }
    }

    @Test
    fun `symmetricRatchet advances symmetric ratchet`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var state1chainKey: ByteArray? = null
        var state1rootKey: ByteArray? = null
        var state1messageKey: ByteArray? = null
        var state1sharedKey: ByteArray? = null
        var state1localPrivateKey: ByteArray? = null
        var state1localEphemeralPublic: ByteArray? = null
        var state1remoteEphemeralPublic: ByteArray? = null

        val bobPublicKeyCopy1 = bobKeypair.publicKeyCopyForTesting
        val bobPublicKeyCopy2 = bobKeypair.publicKeyCopyForTesting

        // Setup: create state with ephemeral keys
        val initialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKeyCopy1)

        val state1 = Ratchet.dhRatchet(
            initialState,
            aliceKeypair,
            bobPublicKeyCopy2,
        )

        assertTrue(state1.localEphemeralKeypair.isDestroyed == false)

        state1rootKey = state1.rootKey.bytesForTesting.copyOf()
        state1chainKey = state1.chainKey?.bytesForTesting?.copyOf()
        state1messageKey = state1.messageKey?.bytesForTesting?.copyOf()
        state1sharedKey = state1.sharedKey?.bytesForTesting?.copyOf()
        state1localEphemeralPublic = state1.localEphemeralKeypair.publicKeyBytesForTesting.copyOf()
        state1remoteEphemeralPublic = state1.remoteEphemeralPublicKey.bytesForTesting.copyOf()

        state1localPrivateKey = state1.localEphemeralKeypair.privateKeyBytesForTesting.copyOf()

        // Advance without new keys
        val state2 = Ratchet.symmetricRatchetFrom(state1)
        val copyOfState2 = RatchetState(state2)
        copyOfState2.use {
            // Message number should increment
            assertEquals(2, state2.messageNumber)

            // Chain key and message key should change
            assertFalse(state1chainKey!!.contentEquals(state2.chainKey!!.bytesForTesting))
            assertFalse(state1messageKey!!.contentEquals(state2.messageKey!!.bytesForTesting))

            // Shared key and ephemeral keys should stay the same - it's not that kind of ratchet
            assertArrayEquals(
                state1sharedKey!!,
                state2.sharedKey!!.bytesForTesting
            )
            assertArrayEquals(
                state1localEphemeralPublic,
                state2.localEphemeralKeypair.publicKeyBytesForTesting
            )

            state2.localEphemeralKeypair.consume { state2PublicKey, state2PrivateKey ->
                assertArrayEquals(
                    state1localPrivateKey,
                    state2PrivateKey.bytesForTesting
                )

                assertArrayEquals(
                    state1remoteEphemeralPublic,
                    state2.remoteEphemeralPublicKey?.bytesForTesting
                )

            }


            // Root key should stay the same
            assertArrayEquals(state1rootKey, state2.rootKey.bytesForTesting)
        }
    }

    @Test
    fun `ratchetWithoutNewKey fails on initial state`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val initialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKey)

            // Should fail because there's no chain key yet
            try {
                Ratchet.symmetricRatchetFrom(initialState)
                fail("Should have thrown IllegalArgumentException")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!.contains("chain key"))
            }
        }

    }

    @Test
    fun `multiple symmetric ratchets produce different keys`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        val bobPublicKey0copy1 = bobKeypair.publicKeyCopyForTesting
        val bobPublicKey0copy2 = bobKeypair.publicKeyCopyForTesting

        val alice0 = Ratchet.initRatchetState(aliceKeypair, bobPublicKey0copy1)
        val alice1 = Ratchet.ratchetForReceive(alice0, bobPublicKey0copy2)

        alice1.use { state1 ->

            val messageKeys = mutableListOf(state1.messageKey!!.bytesForTesting)
            var previousState = RatchetState(state1)

            // Generate 5 more message keys
            repeat(5)
            {

                Ratchet.symmetricRatchetFrom(previousState)
                    .use { newState ->
                        messageKeys.add(newState.messageKey!!.bytesForTesting)
                        previousState = RatchetState(newState)
                    }

            }

            // All message keys should be unique
            for (i in messageKeys.indices) {
                for (j in i + 1 until messageKeys.size) {
                    assertFalse(
                        "Message keys $i and $j should be different",
                        messageKeys[i].contentEquals(messageKeys[j])
                    )
                }
            }
        }
    }

    // ========== Encryption/Decryption Tests ==========

    @Test
    fun `encrypt and decrypt round trip`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair0 = mockEphemeralKeypair()
        val bobKeypair1 = mockEphemeralKeypair()

        val bobPublicKey0 = bobKeypair0.publicKeyCopyForTesting
        val bobPublicKey1 = bobKeypair1.publicKeyCopyForTesting

        val initialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKey0)


        Ratchet.ratchetForReceive(initialState, bobPublicKey1)
            .use { state ->

                val originalMessage = PlaintextMessage(
                    PlaintextMessageType.DATA,
                    "Hello, World!".toByteArray()
                )

                val copyOfPlaintextBytes = originalMessage.bytes.copyOf()

                // Encrypt
                val ciphertext = Encrypt.perform(state.messageKey!!, originalMessage)

                // Decrypt with same key
                val decryptedMessage = Decrypt.perform(state.messageKey!!, ciphertext)

                assertEquals(originalMessage.type, decryptedMessage!!.type)
                assertArrayEquals(copyOfPlaintextBytes, decryptedMessage!!.bytes)
            }
    }

    @Test
    fun `encrypt produces different ciphertext each time`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKey)
            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                Ratchet.ratchetForReceive(secureInitialState, bobPublicKey)
                    .use { state ->

                        val message = PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Same message".toByteArray()
                        )

                        val ciphertext1 = Encrypt.perform(state.messageKey!!, message)
                        val ciphertext2 = Encrypt.perform(state.messageKey!!, message)

                        // Different nonces mean different ciphertexts
                        assertFalse(ciphertext1.nonce.bytes.contentEquals(ciphertext2.nonce.bytes))
                        assertFalse(ciphertext1.encrypted.contentEquals(ciphertext2.encrypted))
                    }
            }
        }
    }

    @Test
    fun `decrypt with wrong key fails`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()
        val copyOfBobPublicKey1: EphemeralPublicKey = bobKeypair.publicKeyCopyForTesting
        val copyOfBobPublicKey2 = bobKeypair.publicKeyCopyForTesting

        val alice0 = Ratchet.initRatchetState(aliceKeypair, copyOfBobPublicKey1)
        val alice1 = Ratchet.ratchetForReceive(alice0, copyOfBobPublicKey2)

        var herFirstMessageKey: MessageKey? = null
        var herSecondMessageKey: MessageKey? = null
        val copyOfAlice1: RatchetState = RatchetState(alice1)

        alice1.use {
            herFirstMessageKey = MessageKey(it.messageKey!!.copyBytes())
        }

        val alice2 = Ratchet.symmetricRatchetFrom(copyOfAlice1)

        alice2.use {
            herSecondMessageKey = MessageKey(it.messageKey!!.copyBytes())
        }

        val message = PlaintextMessage(
            PlaintextMessageType.DATA,
            TestUtils.mockPlaintext().toBytes()
        )

        // Encrypt with the first key
        val ciphertext = Encrypt.perform(herFirstMessageKey!!, message)

        // Try to decrypt with alice2's key (should fail)
        try {
            Decrypt.perform(herSecondMessageKey!!, ciphertext)
                fail("Should have thrown SecurityException")
        }
        catch (e: SecurityException) {
            assertTrue(e.message!!.contains("Authentication"))
        }
    }

    // ========== Protocol Flow Tests ==========

    @Test
    fun `single party can encrypt and decrypt with consistent state`() {
        // This tests that a single party (Alice) can use the ratchet correctly
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(aliceKeypair, bobPublicKey)
            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                Ratchet.ratchetForReceive(secureInitialState, bobPublicKey)
                    .use { state ->

                        // Alice encrypts a message
                        val message = PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Hello!".toByteArray()
                        )
                        val ciphertext = Encrypt.perform(state.messageKey!!, message)

                        // Alice can decrypt with the same key
                        val decrypted = Decrypt.perform(state.messageKey!!, ciphertext)

                        assertEquals(PlaintextMessageType.DATA, decrypted!!.type)
                        assertEquals("Hello!", String(decrypted!!.bytes))
                    }
            }
        }
    }

    @Test
    fun `message exchange with explicit key coordination`() {
        // This demonstrates how the protocol would work with explicit key sharing
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()
        var alice1messageKey: MessageKey? = null

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->
            // Alice initializes and performs first ratchet
            val aliceSecureInitialState =
                Ratchet.initRatchetState(aliceKeypair, bobPublicKey)

            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                val aliceState1 = Ratchet.ratchetForReceive(
                    aliceSecureInitialState,
                    bobPublicKey
                )
                aliceState1.use { aliceState1peek ->

                    // Alice encrypts message 1
                    val message1 =
                        PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Message 1".toByteArray()
                        )
                    val ciphertext1 = Encrypt.perform(aliceState1peek.messageKey!!, message1)
                    alice1messageKey = MessageKey(aliceState1peek.messageKey.bytesForTesting)

                    // Alice advances her ratchet for message 2
                    val aliceState2 = Ratchet.symmetricRatchetFrom(aliceState1)
                    val message2 =
                        PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Message 2".toByteArray()
                        )

                    aliceState2.use { aliceState2peek ->

                        val ciphertext2 =
                            Encrypt.perform(aliceState2peek.messageKey!!, message2)

                        // Both messages can be decrypted with their respective keys
                        val decrypted1 =
                            Decrypt.perform(alice1messageKey!!, ciphertext1)
                        val decrypted2 =
                            Decrypt.perform(aliceState2peek.messageKey!!, ciphertext2)

                        assertEquals("Message 1", String(decrypted1!!.bytes))
                        assertEquals("Message 2", String(decrypted2!!.bytes))

                        // Verify messages can't be decrypted with wrong keys
                        try {
                            Decrypt.perform(aliceState2peek.messageKey!!, ciphertext1)
                            fail("Should not decrypt with wrong key")
                        } catch (e: SecurityException) {
                            // Expected - demonstrates forward secrecy
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `message keys evolve correctly through multiple ratchets`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var bobPublicEphemeralKey: EphemeralPublicKey? = null

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->
            bobPublicEphemeralKey = EphemeralPublicKey(bobPublicKey.copyBytes())
        }

        val initialState = Ratchet.initRatchetState(aliceKeypair, bobPublicEphemeralKey!!)

        Ratchet.ratchetForReceive(initialState, bobPublicEphemeralKey)
        .use { state ->

            assertEquals(1, state.messageNumber)
            var previousState = RatchetState(state)

            // Advance 10 times
            repeat(10) { i ->
                Ratchet.symmetricRatchetFrom(previousState)
                    .use { newState ->
                        assertEquals(i + 2, newState.messageNumber)
                        assertNotNull(newState.messageKey)
                        previousState = RatchetState(newState)
                    }
            }
        }
    }

    @Test
    fun `DH ratchet changes all keys`() {
        val aliceKeypair = TestUtils.mockEphemeralKeypair()
        val bobEphemeral0 = TestUtils.mockEphemeralKeypair()
        val bobEphemeral1 = TestUtils.mockEphemeralKeypair()
        val bobEphemeral2 = TestUtils.mockEphemeralKeypair()

        val initialState = Ratchet.initRatchetState(
            aliceKeypair,
            EphemeralPublicKey(bobEphemeral0.publicKeyBytesForTesting)
        )
        val state1 = Ratchet.ratchetForReceive(
            initialState,
            EphemeralPublicKey(bobEphemeral1.publicKeyBytesForTesting)
        )

        var state1rootKeyBytes: ByteArray? = null
        var state1chainKeyBytes: ByteArray? = null
        var state1sharedKeyBytes: ByteArray? = null
        var state1messageKeyBytes: ByteArray? = null

        val state1copy1 = RatchetState(state1)
        val state1copy2 = RatchetState(state1)

        state1.use {
            state1rootKeyBytes = it.rootKey.bytesForTesting.copyOf()
            state1chainKeyBytes = it.chainKey!!.bytesForTesting.copyOf()
            state1sharedKeyBytes = it.sharedKey!!.bytesForTesting.copyOf()
            state1messageKeyBytes = it.messageKey!!.bytesForTesting.copyOf()
        }

        val state2 = Ratchet.ratchetForReceive(
            state1copy1,
            EphemeralPublicKey(bobEphemeral2.publicKeyBytesForTesting)
        )
        state2.use {
            // All ephemeral keys should be different, changed during the ratchet
            assertFalse(state1rootKeyBytes.contentEquals(it.rootKey.bytesForTesting))
            assertFalse(state1chainKeyBytes.contentEquals(it.chainKey!!.bytesForTesting))
            assertFalse(state1sharedKeyBytes.contentEquals(it.sharedKey!!.bytesForTesting))
            assertFalse(state1messageKeyBytes.contentEquals(it.messageKey!!.bytesForTesting))
            assertNotEquals(state1copy2.remoteEphemeralPublicKey.bytesForTesting, it.remoteEphemeralPublicKey.bytesForTesting)
        }
    }



}