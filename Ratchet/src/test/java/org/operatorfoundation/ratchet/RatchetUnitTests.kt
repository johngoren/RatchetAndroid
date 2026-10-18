package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.ratchet.TestUtils.mockEphemeralKeypair
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.Decrypt
import org.operatorfoundation.ratchet.utils.Encrypt


class RatchetUnitTests {

    // ========== RatchetState Tests ==========

    @Test
    fun `newRatchetState creates initial state with initial ephemeral keys only`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        aliceKeypair.consume { alicePublicKey, alicePrivateKey ->

            bobKeypair.consume { bobPublicKey, bobPrivateKey ->
                val newRatchetState = DoubleRatchet.initRatchetState(
                    aliceKeypair,
                    bobPublicKey
                )

                newRatchetState.use {

                    // Initial state should have ephemeral keys and root key
                    assertNotNull(it.rootKey)
                    assertEquals(32, it.rootKey.bytesForTesting.size)
                    assertArrayEquals(
                        alicePublicKey.bytesForTesting,
                        it.localEphemeralKeypair?.publicKeyBytesForTesting
                    )

                    it.localEphemeralKeypair?.consume { localPublicKey, localPrivateKey ->
                        assertArrayEquals(
                            aliceKeypair.privateKeyBytesForTesting,
                            it.localEphemeralKeypair.privateKeyBytesForTesting
                        )
                    }

                    assertArrayEquals(
                        bobKeypair.publicKeyBytesForTesting,
                        it.remotePublicEphemeralKey?.bytesForTesting
                    )

                    // Ephemeral state should be default
                    assertEquals(0, it.messageNumber)
                    assertNull(it.chainKey)
                    assertNull(it.sharedKey)
                    assertNull(it.messageKey)
                    assertTrue(it.localEphemeralKeypair?.privateKeyBytesForTesting.contentEquals(aliceKeypair.privateKeyBytesForTesting))
                    assertTrue(it.remotePublicEphemeralKey?.bytesForTesting.contentEquals(bobKeypair.publicKeyBytesForTesting))
                }
            }
        }
    }

    @Test
    fun `ratchetForSend generates ephemeral keys and derives chain`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val initialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)

            initialState.use { state0 ->

                var copyOfInitialRootKey = state0.rootKey.bytesForTesting

                // Perform first ratchet with new key
                val result = DoubleRatchet.ratchetForSend(initialState)
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
    }

    @Test
    fun `ratchetForReceive generates state from sender ephemeral key`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var copyOfRootKeyInitial: ByteArray? = null

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->
            val initialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)

            initialState.use {

                copyOfRootKeyInitial = it.rootKey.bytesForTesting.copyOf()

                // Bob sends his ephemeral key
                val bobEphemeralKeypair = mockEphemeralKeypair()

                bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                    DoubleRatchet.ratchetForReceive(it, bobPublicKey)
                        .use { ratchetedState ->

                            assertNotNull(ratchetedState.chainKey)
                            assertNotNull(ratchetedState.sharedKey)
                            assertNotNull(ratchetedState.messageKey)
                            assertNotNull(ratchetedState.remotePublicEphemeralKey)

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

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            // Setup: create state with ephemeral keys
            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)

            val secureState1 = DoubleRatchet.dhRatchet(
                secureInitialState,
                aliceKeypair,
                bobPublicKey,
            )

            secureState1.use { state1 ->
                assertTrue(state1.localEphemeralKeypair?.isDestroyed == false)

                state1rootKey = state1.rootKey.bytesForTesting.copyOf()
                state1chainKey = state1.chainKey?.bytesForTesting?.copyOf()
                state1messageKey = state1.messageKey?.bytesForTesting?.copyOf()
                state1sharedKey = state1.sharedKey?.bytesForTesting?.copyOf()
                state1localEphemeralPublic = state1.localEphemeralKeypair?.publicKeyBytesForTesting?.copyOf()
                state1remoteEphemeralPublic = state1.remotePublicEphemeralKey?.bytesForTesting?.copyOf()

                state1localPrivateKey = state1.localEphemeralKeypair?.privateKeyBytesForTesting?.copyOf()

                // Advance without new keys
                DoubleRatchet.symmetricRatchet(secureState1).use { state2 ->

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
                        state2.localEphemeralKeypair?.publicKeyBytesForTesting
                    )

                    state2.localEphemeralKeypair?.consume { state2PublicKey, state2PrivateKey ->
                        assertArrayEquals(
                            state1localPrivateKey,
                            state2PrivateKey.bytesForTesting
                        )

                        assertArrayEquals(
                            state1remoteEphemeralPublic,
                            state2.remotePublicEphemeralKey?.bytesForTesting
                        )

                    }


                    // Root key should stay the same
                    assertArrayEquals(state1rootKey, state2.rootKey.bytesForTesting)
                }
            }
        }
    }

    @Test
    fun `ratchetWithoutNewKey fails on initial state`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val initialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)

            // Should fail because there's no chain key yet
            try {
                DoubleRatchet.symmetricRatchet(initialState)
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

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)
            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                secureInitialState.use { initialState ->

                    DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey)
                        .use { state ->

                            val messageKeys = mutableListOf(state.messageKey!!.bytesForTesting)
                            var previousState = state

                            // Generate 5 more message keys
                            repeat(5)
                            {

                                DoubleRatchet.symmetricRatchet(previousState)
                                    .use { newState ->
                                        messageKeys.add(newState.messageKey!!.bytesForTesting)
                                        previousState = newState
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
            }
        }
    }

    // ========== Encryption/Decryption Tests ==========

    @Test
    fun `encrypt and decrypt round trip`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)
            secureInitialState.use { initialState ->
                val bobEphemeralKeypair = mockEphemeralKeypair()
                bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->
                    DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey)
                        .use { state ->

                            val originalMessage = PlaintextMessage(
                                PlaintextMessageType.DATA,
                                "Hello, World!".toByteArray()
                            )

                            // Encrypt
                            val ciphertext = Encrypt.perform(state.messageKey!!, originalMessage)

                            // Decrypt with same key
                            val decryptedMessage = Decrypt.perform(state.messageKey!!, ciphertext)

                            assertEquals(originalMessage.type, decryptedMessage!!.type)
                            assertArrayEquals(originalMessage.bytes, decryptedMessage!!.bytes)
                        }
                }
            }
        }
    }

    @Test
    fun `encrypt produces different ciphertext each time`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)
            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey)
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

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)
            val bobEphemeralKeypair = mockEphemeralKeypair()


            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey)
                    .use { state1 ->
                        val state2 =
                            DoubleRatchet.symmetricRatchet(state1)

                        val message = PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Secret".toByteArray()
                        )

                        // Encrypt with state1's key
                        val ciphertext = Encrypt.perform(state1.messageKey!!, message)

                        // Try to decrypt with state2's key (should fail)
                        try {
                            state2.use { state2peek ->
                                Decrypt.perform(state2peek.messageKey!!, ciphertext)
                                fail("Should have thrown SecurityException")
                            }
                        } catch (e: SecurityException) {
                            assertTrue(e.message!!.contains("Authentication"))
                        }
                    }
            }
        }

    }

    // ========== Protocol Flow Tests ==========

    @Test
    fun `single party can encrypt and decrypt with consistent state`() {
        // This tests that a single party (Alice) can use the ratchet correctly
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)
            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey)
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
                DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)

            val bobEphemeralKeypair = mockEphemeralKeypair()

            bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                val aliceState1 = DoubleRatchet.ratchetForReceive(
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
                    val aliceState2 = DoubleRatchet.symmetricRatchet(aliceState1)
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

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey)

            secureInitialState.use { initialState ->
                val bobEphemeralKeypair = mockEphemeralKeypair()

                bobEphemeralKeypair.consume { bobPublicKey, bobPrivateKey ->

                    DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey)
                        .use { state ->

                            assertEquals(1, state.messageNumber)
                            var previousState = state

                            // Advance 10 times
                            repeat(10) { i ->
                                DoubleRatchet.symmetricRatchet(previousState)
                                    .use { newState ->
                                        assertEquals(i + 2, newState.messageNumber)
                                        assertNotNull(newState.messageKey)
                                        previousState = newState
                                    }
                            }
                        }
                }
            }
        }
    }

    @Test
    fun `DH ratchet changes all keys`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()
        val bobEphemeral1 = mockEphemeralKeypair()
        val bobEphemeral2 = mockEphemeralKeypair()

        var state1RootKey: ByteArray? = null
        var state1ChainKey: ByteArray? = null
        var state1SharedKey: ByteArray? = null
        var state1MessageKey: ByteArray? = null
        var state1RemoteEphemeralPublicKey: ByteArray? = null

        var state2RootKey: ByteArray? = null
        var state2ChainKey: ByteArray? = null
        var state2SharedKey: ByteArray? = null

        bobKeypair.consume { bobPublicKey0, bobPrivateKey ->

            bobEphemeral1.consume { bobPublicKey1, bobPrivateKey1 ->

                bobEphemeral2.consume { bobPublicKey2, bobPrivateKey2 ->

                    val secureInitialState =
                        DoubleRatchet.initRatchetState(aliceKeypair, bobPublicKey0)

                    secureInitialState.use { initialState ->

                        val state1 =
                            DoubleRatchet.ratchetForReceive(secureInitialState, bobPublicKey1)
                        state1.use { state1peek ->

                            state1RootKey = state1peek.rootKey.bytesForTesting
                            state1ChainKey = state1peek.chainKey?.bytesForTesting
                            state1SharedKey = state1peek.sharedKey?.bytesForTesting
                            state1MessageKey = state1peek.messageKey?.bytesForTesting
                            state1RemoteEphemeralPublicKey = state1peek.remotePublicEphemeralKey?.bytesForTesting

                            DoubleRatchet.ratchetForReceive(state1, bobPublicKey2)
                                .use { state2 ->

                                    // All ephemeral keys should be different
                                    assertFalse(state1RootKey.contentEquals(state2.rootKey.bytesForTesting))
                                    assertFalse(state1ChainKey.contentEquals(state2.chainKey!!.bytesForTesting))
                                    assertFalse(
                                        state1SharedKey.contentEquals(
                                            state2.sharedKey!!.bytesForTesting
                                        )
                                    )
                                    assertFalse(
                                        state1MessageKey!!.contentEquals(
                                            state2.messageKey!!.bytesForTesting
                                        )
                                    )
                                    assertNotEquals(
                                        state1RemoteEphemeralPublicKey,
                                        state2.remotePublicEphemeralKey
                                    )
                                }
                        }
                    }
                }
            }
        }
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
            assertTrue(e.message!!.contains("security"))
        }

        try {
            (key1 == key2)
            fail("Should have thrown SecurityException")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("security"))
        }
    }

    // ========== Zeroization tests ==========


}