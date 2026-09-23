package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState

class RatchetIntegrationTest {
    @Test
    fun `newRatchetState creates valid initial state`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val singleUseRatchetState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            try {
                singleUseRatchetState.use { state ->
                    assertNotNull(state.rootKey)
                    assertEquals(0, state.messageNumber)

                    // Ephemeral keys are not yet generated
                    assertNull(state.chainKey)
                    assertNull(state.sharedKey)
                    assertNull(state.messageKey)
                    assertNull(state.localEphemeralKeypair)
                    assertNull(state.remoteEphemeralPublicKey)
                }
            } catch (e: Exception) {

            } finally {
                singleUseRatchetState.close()
            }
        }
    }

    @Test
    fun `both parties derive same initial root key`() {
        val aliceSecureKeypair = Ratchet.generateMADHKeypair()
        val bobSecureKeypair = Ratchet.generateMADHKeypair()

        aliceSecureKeypair.use { aliceKeypair ->

            bobSecureKeypair.use { bobKeypair ->

                val aliceSingleUseRatchetState = Ratchet.newRatchetState(
                    aliceSecureKeypair,
                    bobKeypair.publicKey
                )

                val bobSingleUseRatchetState = Ratchet.newRatchetState(
                    bobSecureKeypair,
                    aliceKeypair.publicKey
                )

                var aliceRootKey: ByteArray? = null
                var bobRootKey: ByteArray? = null

                aliceSingleUseRatchetState.use { aliceState ->
                    aliceRootKey = aliceState.rootKey.bytes

                    bobSingleUseRatchetState.use { bobState ->
                        bobRootKey = bobState.rootKey.bytes

                        // Both should derive the same root key (ECDH is commutative)
                        assertArrayEquals(aliceRootKey!!, bobRootKey!!)
                    }
                }
            }
        }
    }

    @Test
    fun `ratchetForSend performs DH ratchet step`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            var newState: RatchetState? = null

            secureInitialState.use { initialState ->
                val result = Ratchet.ratchetForSend(secureInitialState)
                assertNotNull(result.ephemeralPublicKeyToSend)

                result.state.use { newState ->

                    // Root key should change
                    assertFalse(initialState.rootKey.bytes.contentEquals(newState.rootKey.bytes))

                    // All keys should be created after DH ratchet
                    assertNotNull(newState!!.chainKey)
                    assertNotNull(newState.sharedKey)
                    assertNotNull(newState.messageKey)


                    // Message number should increment
                    assertEquals(1, newState.messageNumber)
                }

            }
        }
    }


    @Test
    fun `ratchetForReceive performs DH ratchet step`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            secureInitialState.use { initialState ->

                val senderEphemeralKey = MADH.generateKeypair().publicKey

                Ratchet.ratchetForReceive(secureInitialState, senderEphemeralKey).use { newState ->

                    // All keys should be created after DH ratchet
                    assertNotNull(newState.chainKey)
                    assertNotNull(newState.sharedKey)
                    assertNotNull(newState.messageKey)
                    assertNotNull(newState.remoteEphemeralPublicKey)

                    // Root key should change
                    assertFalse(initialState.rootKey.bytes.contentEquals(newState.rootKey.bytes))

                    // Message number should increment
                    assertEquals(1, newState.messageNumber)
                }
            }
        }
    }

    @Test
    fun `ratchetWithoutNewKey performs symmetric ratchet step`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            // Need to do DH ratchet first to get ephemeral keys
            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            secureInitialState.use { initialState ->
                val senderEphemeralKey = MADH.generateKeypair().publicKey
                val state1 = Ratchet.ratchetForReceive(secureInitialState, senderEphemeralKey)
                state1.use { state1Snapshot ->

                    Ratchet.symmetricRatchet(state1).use { state2 ->
                        // Chain and message keys should change (symmetric ratchet)
                        assertFalse(state1Snapshot.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
                        assertFalse(state1Snapshot.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))

                        // Root key, shared key, and ephemeral keys should remain unchanged
                        assertArrayEquals(state1Snapshot.rootKey.bytes, state2.rootKey.bytes)
                        assertArrayEquals(
                            state1Snapshot.sharedKey!!.bytes,
                            state2.sharedKey!!.bytes
                        )
                        assertArrayEquals(
                            state1Snapshot.localEphemeralKeypair?.publicKey?.bytes,
                            state2.localEphemeralKeypair?.publicKey?.bytes
                        )
                        assertArrayEquals(
                            state1Snapshot.localEphemeralKeypair?.privateKey?.bytes,
                            state2.localEphemeralKeypair?.privateKey?.bytes
                        )
                        assertArrayEquals(
                            state1Snapshot.remoteEphemeralPublicKey?.bytes,
                            state2.remoteEphemeralPublicKey?.bytes
                        )

                        // Message number should increment
                        assertEquals(2, state2.messageNumber)
                    }
                }
            }
        }
    }

    @Test
    fun `encrypt and decrypt round trip preserves message`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            secureInitialState.use { initialState ->
                // Need to perform DH ratchet first to get a message key
                val result = Ratchet.ratchetForSend(secureInitialState)
                result.state.use { state ->
                    val originalMessage = PlaintextMessage(
                        type = PlaintextMessageType.UNCOMPRESSED_TEXT,
                        bytes = "Hello, World!".toByteArray()
                    )

                    val ciphertext = Ratchet.encrypt(state.messageKey!!, originalMessage)
                    val decryptedMessage = Ratchet.decrypt(state.messageKey!!, ciphertext)

                    assertEquals(originalMessage.type, decryptedMessage!!.type)
                    assertArrayEquals(originalMessage.bytes, decryptedMessage!!.bytes)
                }
            }
        }
    }

    @Test
    fun `multiple messages can be sent with symmetric ratcheting`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            secureInitialState.use { initialState ->

                // Perform initial DH ratchet
                val result = Ratchet.ratchetForSend(secureInitialState)
                var currentState = result.state

                val messages = listOf("First", "Second", "Third")

                for (messageText in messages) {
                    val plaintext = PlaintextMessage(
                        PlaintextMessageType.UNCOMPRESSED_TEXT,
                        messageText.toByteArray()
                    )

                    currentState.use { currentStateSnapshot ->
                        val ciphertext =
                            Ratchet.encrypt(currentStateSnapshot.messageKey!!, plaintext)
                        val decrypted =
                            Ratchet.decrypt(currentStateSnapshot.messageKey!!, ciphertext)

                        assertArrayEquals(plaintext.bytes, decrypted!!.bytes)

                        // Advance ratchet for next message
                        Ratchet.symmetricRatchet(currentState).use { newState ->
                            currentState = SecureRatchetState(newState)
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `Alice can send multiple messages to herself`() {
        // This test demonstrates single-party usage

        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val aliceSecureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            val result = Ratchet.ratchetForSend(aliceSecureInitialState)

            result.state.use { aliceState ->

                // Alice sends first message
                val message1 = PlaintextMessage(
                    PlaintextMessageType.UNCOMPRESSED_TEXT,
                    "Hello Bob".toByteArray()
                )
                val ciphertext1 = Ratchet.encrypt(aliceState.messageKey!!, message1)
                val decrypted1 = Ratchet.decrypt(aliceState.messageKey!!, ciphertext1)
                assertArrayEquals(message1.bytes, decrypted1!!.bytes)

                Ratchet.symmetricRatchet(result.state).use { newState ->

                    val message2 = PlaintextMessage(
                        PlaintextMessageType.UNCOMPRESSED_TEXT,
                        "Hello again".toByteArray()
                    )
                    val ciphertext2 = Ratchet.encrypt(newState.messageKey!!, message2)
                    val decrypted2 = Ratchet.decrypt(newState.messageKey!!, ciphertext2)
                    assertArrayEquals(message2.bytes, decrypted2!!.bytes)
                }
            }
        }
    }

    @Test
    fun `DH ratchet provides forward secrecy`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            secureInitialState.use { initialState ->
                // Perform first DH ratchet with ephemeral keys
                val result1 = Ratchet.ratchetForSend(secureInitialState)
                val state1 = result1.state
                state1.use {
                    state1Snapshot ->
                    // Perform second DH ratchet with new ephemeral keys
                    val result2 = Ratchet.ratchetForSend(state1)
                    result2.state.use { state2 ->

                        // All keys should be completely different (forward secrecy)
                        assertFalse(state1Snapshot.rootKey.bytes.contentEquals(state2.rootKey.bytes))
                        assertFalse(state1Snapshot.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
                        assertFalse(state1Snapshot.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))
                        assertFalse(state1Snapshot.sharedKey!!.bytes.contentEquals(state2.sharedKey!!.bytes))

                        // The ephemeral keys should be different
                        assertFalse(result1.ephemeralPublicKeyToSend.bytes.contentEquals(result2.ephemeralPublicKeyToSend.bytes))
                    }
                }
            }
        }
    }

    @Test
    fun `same plaintext with different keys produces different ciphertexts`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->
            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            val result = Ratchet.ratchetForSend(secureInitialState)

            result.state.use { stateSnapshot ->

                val message = PlaintextMessage(
                    type = PlaintextMessageType.UNCOMPRESSED_TEXT,
                    bytes = "Same message".toByteArray()
                )

                val ciphertext1 = Ratchet.encrypt(stateSnapshot.messageKey!!, message)

                // Advance ratchet to get new message key
                Ratchet.symmetricRatchet(result.state).use { newState ->
                    val ciphertext2 = Ratchet.encrypt(newState.messageKey!!, message)

                    // Same plaintext with different keys should produce different ciphertexts
                    assertFalse(ciphertext1.encrypted.contentEquals(ciphertext2.encrypted))
                    assertFalse(ciphertext1.nonce.bytes.contentEquals(ciphertext2.nonce.bytes))
                }
            }
        }
    }

    @Test
    fun `different message types can be encrypted and decrypted`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
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
                    val ciphertext = Ratchet.encrypt(state.messageKey!!, message)
                    val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

                    assertEquals(messageType, decrypted!!.type)
                    assertArrayEquals("test".toByteArray(), decrypted!!.bytes)
                }
            }
        }
    }

    @Test
    fun `message numbers increment correctly through ratcheting`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            secureInitialState.use { initialState ->

                assertEquals(0, initialState.messageNumber)

                // DH ratchet increments to 1
                val result = Ratchet.ratchetForSend(secureInitialState)

                result.state.use { state ->
                    assertEquals(1, state.messageNumber)

                    var currentState = SecureRatchetState(state)

                    // Symmetric ratchets increment by 1 each
                    for (i in 2..10) {
                        Ratchet.symmetricRatchet(currentState).use { newState ->
                            assertEquals(i, newState.messageNumber)
                            currentState = SecureRatchetState(newState.deepCopy())
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `cannot decrypt with wrong key`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            val result = Ratchet.ratchetForSend(secureInitialState)
            val state1 = result.state

            state1.use { state1Snapshot ->

                Ratchet.symmetricRatchet(state1).use { state2 ->
                    val message = PlaintextMessage(
                        PlaintextMessageType.DATA,
                        "Secret".toByteArray()
                    )

                    // Encrypt with state1's key
                    val ciphertext = Ratchet.encrypt(state1Snapshot.messageKey!!, message)

                    // Try to decrypt with state2's key (should fail)
                    try {
                        Ratchet.decrypt(state2.messageKey!!, ciphertext)
                        fail("Should have thrown SecurityException")
                    } catch (e: SecurityException) {
                        assertTrue(e.message!!.contains("Authentication"))
                    }
                }
            }
        }
    }

}