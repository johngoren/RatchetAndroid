package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.TestUtils.mockEphemeralKeypair
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.Decrypt
import org.operatorfoundation.ratchet.utils.Encrypt


class RatchetIntegrationTest {

    @Test
    fun `both parties derive same initial root key`() {
        val aliceSecureKeypair = mockEphemeralKeypair()
        val bobSecureKeypair = mockEphemeralKeypair()

        aliceSecureKeypair.consume { alicePublicKey, alicePrivateKey ->

            bobSecureKeypair.consume { bobPublicKey, bobPrivateKey  ->

                val aliceSingleUseRatchetState = Ratchet.initRatchetState(
                    aliceSecureKeypair,
                    bobPublicKey
                )

                val bobSingleUseRatchetState = Ratchet.initRatchetState(
                    bobSecureKeypair,
                    alicePublicKey
                )

                var aliceRootKey: ByteArray? = null
                var bobRootKey: ByteArray? = null

                aliceSingleUseRatchetState.use { aliceState ->
                    aliceRootKey = aliceState.rootKey.bytesForTesting

                    bobSingleUseRatchetState.use { bobState ->
                        bobRootKey = bobState.rootKey.bytesForTesting

                        // Both should derive the same root key (ECDH is commutative)
                        assertArrayEquals(aliceRootKey!!, bobRootKey!!)
                    }
                }
            }
        }
    }

    @Test
    fun `ratchetForSend performs DH ratchet step`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            secureInitialState.use { state0 ->
                val copyOfState0RootKey = state0.rootKey.bytesForTesting.copyOf()
                val state1Result = Ratchet.ratchetForSend(secureInitialState)
                assertNotNull(state1Result.newEphemeralPublicKey)

                state1Result.state.use { state1 ->

                    // Root key should change
                    assertFalse(copyOfState0RootKey.contentEquals(state1.rootKey.bytesForTesting))

                    // All keys should be created after DH ratchet
                    assertNotNull(state1.chainKey)
                    assertNotNull(state1.sharedKey)
                    assertNotNull(state1.messageKey)


                    // Message number should increment
                    assertEquals(1, state1.messageNumber)
                }

            }
        }
    }


    @Test
    fun `ratchetForReceive performs DH ratchet step`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()
        var initialStateRootKey: ByteArray? = null

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            secureInitialState.use { initialState ->

                val senderEphemeralKey = EphemeralPublicKey(MADH.generateKeypair().publicKey.bytes)
                initialStateRootKey = initialState.rootKey.bytesForTesting

                Ratchet.ratchetForReceive(secureInitialState, senderEphemeralKey).use { newState ->

                    // All keys should be created after DH ratchet
                    assertNotNull(newState.chainKey)
                    assertNotNull(newState.sharedKey)
                    assertNotNull(newState.messageKey)
//                    assertNotNull(newState.localEphemeralKeypair)
                    assertNotNull(newState.remoteEphemeralPublicKey)

                    // Root key should change
                    assertFalse(initialStateRootKey.contentEquals(newState.rootKey.bytesForTesting))

                    // Message number should increment
                    assertEquals(1, newState.messageNumber)

                }
            }
        }
    }


    @Test
    fun `ratchetWithoutNewKey performs symmetric ratchet step`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        val incomingEphemeralKey = EphemeralPublicKey(MADH.generateKeypair().publicKey.bytes)

        var bobPublicKey: EphemeralPublicKey? = null

        bobKeypair.consume { publicKey, privateKey ->
            bobPublicKey = publicKey
        }

        // Need to do DH ratchet first to get ephemeral keys
        val initialState = Ratchet.initRatchetState(
            aliceKeypair,
            bobPublicKey!!
        )

        val state1 = Ratchet.dhRatchet(
            initialState, aliceKeypair, incomingEphemeralKey)

        var state1chainKey: ByteArray? = null
        var state1rootKey: ByteArray? = null
        var state1messageKey: ByteArray? = null
        var state1sharedKey: ByteArray? = null
        var state1localPublicKey: ByteArray? = null
        var state1localPrivateKey: ByteArray? = null
        var state1remoteEphemeralPublicKey: ByteArray? = null

        state1.use { state1Peek ->

            state1Peek.apply {
                state1chainKey = chainKey?.bytesForTesting?.copyOf()
                state1rootKey = rootKey.bytesForTesting.copyOf()
                state1messageKey = messageKey?.bytesForTesting?.copyOf()
                state1sharedKey = sharedKey?.bytesForTesting?.copyOf()
                state1localPublicKey = localEphemeralKeypair?.publicKeyBytesForTesting?.copyOf()
                state1localPrivateKey = localEphemeralKeypair?.privateKeyBytesForTesting?.copyOf()
                state1remoteEphemeralPublicKey = remoteEphemeralPublicKey?.bytesForTesting?.copyOf()
            }

            Ratchet.symmetricRatchetFrom(state1).use { state2 ->
                // Chain and message keys should change (symmetric ratchet)
                assertFalse(state1chainKey!!.contentEquals(state2.chainKey!!.bytesForTesting))
                assertFalse(state1messageKey!!.contentEquals(state2.messageKey!!.bytesForTesting))

                // Root key, shared key, and ephemeral keys should remain unchanged
                assertArrayEquals(state1rootKey, state2.rootKey.bytesForTesting)
                assertArrayEquals(
                    state1sharedKey!!,
                    state2.sharedKey!!.bytesForTesting
                )
                assertArrayEquals(
                    state1localPublicKey,
                    state2.localEphemeralKeypair?.publicKeyBytesForTesting
                )
                state2.localEphemeralKeypair?.consume { state2PublicKey, state2PrivateKey ->
                    assertArrayEquals(
                        state1localPrivateKey,
                        state2PrivateKey.bytesForTesting
                    )
                }
                assertArrayEquals(
                    state1remoteEphemeralPublicKey,
                    state2.remoteEphemeralPublicKey?.bytesForTesting
                )

                // Message number should increment
                assertEquals(2, state2.messageNumber)
            }
        }
    }

    @Test
    fun `encrypt and decrypt round trip preserves message`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            secureInitialState.use { initialState ->
                // Need to perform DH ratchet first to get a message key
                val result = Ratchet.ratchetForSend(secureInitialState)
                result.state.use { state ->
                    val originalMessage = PlaintextMessage(
                        type = PlaintextMessageType.UNCOMPRESSED_TEXT,
                        bytes = "Hello, World!".toByteArray()
                    )

                    val ciphertext = Encrypt.perform(state.messageKey!!, originalMessage)
                    val decryptedMessage = Decrypt.perform(state.messageKey!!, ciphertext)

                    assertEquals(originalMessage.type, decryptedMessage!!.type)
                    assertArrayEquals(originalMessage.bytes, decryptedMessage!!.bytes)
                }
            }
        }
    }

    @Test
    fun `multiple messages can be sent with symmetric ratcheting`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        lateinit var copyOfBobPublicKey: EphemeralPublicKey
        bobKeypair.consume { bobPublicKey, bobPrivateKey ->
            copyOfBobPublicKey = bobPublicKey
        }

        val initialState = Ratchet.initRatchetState(
            aliceKeypair,
            copyOfBobPublicKey
        )

        initialState.use { initialState ->

            // Perform initial DH ratchet
            val result = Ratchet.ratchetForSend(initialState)
            var currentState = RatchetState(result.state)

            val messages = listOf("First", "Second", "Third")

            for (messageText in messages) {
                val plaintext = PlaintextMessage(
                    PlaintextMessageType.UNCOMPRESSED_TEXT,
                    messageText.toByteArray()
                )

                currentState.use { currentStatePeek ->
                    val ciphertext =
                        Encrypt.perform(currentStatePeek.messageKey!!, plaintext)
                    val decrypted =
                        Decrypt.perform(currentStatePeek.messageKey!!, ciphertext)

                    assertArrayEquals(plaintext.bytes, decrypted!!.bytes)

                    // Advance ratchet for next message
                    Ratchet.symmetricRatchetFrom(currentState).use {
                        currentState = RatchetState(it)
                    }
                }
            }
        }
    }

    @Test
    fun `Alice can send multiple messages to herself`() {
        // This test demonstrates single-party usage

        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val aliceSecureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            val result = Ratchet.ratchetForSend(aliceSecureInitialState)

            result.state.use { aliceState ->

                // Alice sends first message
                val message1 = PlaintextMessage(
                    PlaintextMessageType.UNCOMPRESSED_TEXT,
                    "Hello Bob".toByteArray()
                )
                val ciphertext1 = Encrypt.perform(aliceState.messageKey!!, message1)
                val decrypted1 = Decrypt.perform(aliceState.messageKey!!, ciphertext1)
                assertArrayEquals(message1.bytes, decrypted1!!.bytes)

                Ratchet.symmetricRatchetFrom(result.state).use { newState ->

                    val message2 = PlaintextMessage(
                        PlaintextMessageType.UNCOMPRESSED_TEXT,
                        "Hello again".toByteArray()
                    )
                    val ciphertext2 = Encrypt.perform(newState.messageKey!!, message2)
                    val decrypted2 = Decrypt.perform(newState.messageKey!!, ciphertext2)
                    assertArrayEquals(message2.bytes, decrypted2!!.bytes)
                }
            }
        }
    }

    @Test
    fun `DH ratchet provides forward secrecy`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var copyOfBobPublicKey: EphemeralPublicKey? = null

        bobKeypair.consume { bobPublicKey, _ ->
            copyOfBobPublicKey = EphemeralPublicKey(bobPublicKey.bytesForTesting)
        }

        val initialState = Ratchet.initRatchetState(
            aliceKeypair,
            copyOfBobPublicKey!!
        )

        // Perform first DH ratchet with ephemeral keys
        val result1 = Ratchet.ratchetForSend(initialState)
        val state1 = result1.state
        val state1copy = RatchetState(state1)

        // Perform second DH ratchet with new ephemeral keys
        val result2 = Ratchet.ratchetForSend(state1)
        result2.state.use { state2 ->
            // All keys should be completely different (forward secrecy)
            assertFalse(state1copy.rootKey.bytesForTesting.contentEquals(state2.rootKey.bytesForTesting))
            assertFalse(state1copy.chainKey!!.bytesForTesting.contentEquals(state2.chainKey!!.bytesForTesting))
            assertFalse(state1copy.messageKey!!.bytesForTesting.contentEquals(state2.messageKey!!.bytesForTesting))
            assertFalse(state1copy.sharedKey!!.bytesForTesting.contentEquals(state2.sharedKey!!.bytesForTesting))

            // The ephemeral keys should be different
            assertFalse(result1.newEphemeralPublicKey.bytesForTesting.contentEquals(result2.newEphemeralPublicKey.bytesForTesting))
        }
    }

    @Test
    fun `same plaintext with different keys produces different ciphertexts`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->
            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            val result = Ratchet.ratchetForSend(secureInitialState)

            result.state.use { statePeek ->

                val message = PlaintextMessage(
                    type = PlaintextMessageType.UNCOMPRESSED_TEXT,
                    bytes = "Same message".toByteArray()
                )

                val ciphertext1 = Encrypt.perform(statePeek.messageKey!!, message)

                // Advance ratchet to get new message key
                Ratchet.symmetricRatchetFrom(result.state).use { newState ->
                    val ciphertext2 = Encrypt.perform(newState.messageKey!!, message)

                    // Same plaintext with different keys should produce different ciphertexts
                    assertFalse(ciphertext1.encrypted.contentEquals(ciphertext2.encrypted))
                    assertFalse(ciphertext1.nonce.bytes.contentEquals(ciphertext2.nonce.bytes))
                }
            }
        }
    }

    @Test
    fun `different message types can be encrypted and decrypted`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )


            val result = Ratchet.ratchetForSend(secureInitialState)
            result.state.use { state ->

                val messageTypes = listOf(
                    PlaintextMessageType.HANDSHAKE,
                    PlaintextMessageType.RATCHET,
                    PlaintextMessageType.ERROR,
                    PlaintextMessageType.COMPRESSED_TEXT,
                    PlaintextMessageType.UNCOMPRESSED_TEXT,
                    PlaintextMessageType.DATA
                )

                for (messageType in messageTypes) {
                    val message = PlaintextMessage(messageType, "test".toByteArray())
                    val ciphertext = Encrypt.perform(state.messageKey!!, message)
                    val decrypted = Decrypt.perform(state.messageKey!!, ciphertext)

                    assertEquals(messageType, decrypted!!.type)
                    assertArrayEquals("test".toByteArray(), decrypted!!.bytes)
                }
            }
        }
    }

    @Test
    fun `message numbers increment correctly through ratcheting`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            secureInitialState.use { initialState ->

                assertEquals(0, initialState.messageNumber)

                // DH ratchet increments to 1
                val result = Ratchet.ratchetForSend(secureInitialState)

                result.state.use {
                    assertEquals(1, it.messageNumber)

                    var currentState = it

                    // Symmetric ratchets increment by 1 each
                    for (i in 2..10) {
                        Ratchet.symmetricRatchetFrom(currentState).use {
                            assertEquals(i, it.messageNumber)
                            currentState = RatchetState(it)
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `cannot decrypt with wrong key`() {
        val aliceKeypair = mockEphemeralKeypair()
        val bobKeypair = mockEphemeralKeypair()

        var state1messageKey: MessageKey

        bobKeypair.consume { bobPublicKey, bobPrivateKey ->

            val secureInitialState = Ratchet.initRatchetState(
                aliceKeypair,
                bobPublicKey
            )

            val result = Ratchet.ratchetForSend(secureInitialState)
            val state1 = result.state

            state1.use { state1Peek ->

                state1messageKey = MessageKey(state1Peek.messageKey?.bytesForTesting!!)

                Ratchet.symmetricRatchetFrom(state1).use { state2 ->
                    val message = PlaintextMessage(
                        PlaintextMessageType.DATA,
                        "Secret".toByteArray()
                    )

                    // Encrypt with state1's key
                    val ciphertext = Encrypt.perform(state1messageKey, message)

                    // Try to decrypt with state2's key (should fail)
                    try {
                        Decrypt.perform(state2.messageKey!!, ciphertext)
                        fail("Should have thrown SecurityException")
                    } catch (e: SecurityException) {
                        assertTrue(e.message!!.contains("Authentication"))
                    }
                }
            }
        }
    }
}