package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.PlaintextMessageType
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState
import kotlin.test.assertFailsWith

// TODO: Test zeroization!

class RatchetUnitTests
{
    // ========== PlaintextMessageType Tests ==========

    @Test
    fun `PlaintextMessageType has correct byte values`()
    {
        assertEquals(0x48.toByte(), PlaintextMessageType.HANDSHAKE.value)
        assertEquals(0x52.toByte(), PlaintextMessageType.RATCHET.value)
        assertEquals(0x45.toByte(), PlaintextMessageType.ERROR.value)
        assertEquals(0x43.toByte(), PlaintextMessageType.COMPRESSED_TEXT.value)
        assertEquals(0x55.toByte(), PlaintextMessageType.UNCOMPRESSED_TEXT.value)
        assertEquals(0x44.toByte(), PlaintextMessageType.DATA.value)
    }

    @Test
    fun `PlaintextMessageType fromByte returns correct type`()
    {
        assertEquals(PlaintextMessageType.HANDSHAKE, PlaintextMessageType.fromByte(0x48))
        assertEquals(PlaintextMessageType.RATCHET, PlaintextMessageType.fromByte(0x52))
        assertEquals(PlaintextMessageType.ERROR, PlaintextMessageType.fromByte(0x45))
        assertEquals(PlaintextMessageType.COMPRESSED_TEXT, PlaintextMessageType.fromByte(0x43))
        assertEquals(PlaintextMessageType.UNCOMPRESSED_TEXT, PlaintextMessageType.fromByte(0x55))
        assertEquals(PlaintextMessageType.DATA, PlaintextMessageType.fromByte(0x44))
    }

    @Test
    fun `PlaintextMessageType fromByte returns null for invalid byte`()
    {
        assertNull(PlaintextMessageType.fromByte(0x00))
        assertNull(PlaintextMessageType.fromByte(0xFF.toByte()))
    }

    // ========== PlaintextMessage Tests ==========

    @Test
    fun `PlaintextMessage serialization and deserialization round trip`()
    {
        val originalMessage = PlaintextMessage(
            PlaintextMessageType.DATA,
            "Hello, World!".toByteArray()
        )

        val serialized = originalMessage.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)

        assertEquals(originalMessage.type, deserialized.type)
        assertArrayEquals(originalMessage.bytes, deserialized.bytes)
    }

    @Test
    fun `PlaintextMessage handles empty content`()
    {
        val message = PlaintextMessage(PlaintextMessageType.ERROR, byteArrayOf())
        val serialized = message.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)

        assertEquals(PlaintextMessageType.ERROR, deserialized.type)
        assertArrayEquals(byteArrayOf(), deserialized.bytes)
    }

    @Test
    fun `PlaintextMessage handles large content`()
    {
        val largeContent = ByteArray(10000) { it.toByte() }
        val message = PlaintextMessage(PlaintextMessageType.DATA, largeContent)

        val serialized = message.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)

        assertEquals(PlaintextMessageType.DATA, deserialized.type)
        assertArrayEquals(largeContent, deserialized.bytes)
    }

    @Test
    fun `PlaintextMessage will refuse to serialize content that exceeds size limit`()
    {
        val excessivelyLongContent = ByteArray(5000000)
        val message = PlaintextMessage(PlaintextMessageType.DATA, bytes = excessivelyLongContent)

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                message.toBytes()
            }
        )
    }

    @Test
    fun `PlaintextMessage will refuse to deserialize content beyond its size limits`()
    {
        val basicContent = ByteArray(100)
        val validWireMessage = PlaintextMessage(PlaintextMessageType.DATA, basicContent).toBytes()

        assert(validWireMessage[0].toInt() == 1)

        val invalidNumOfBytes = 0x05
        val invalidMessage1 = validWireMessage.copyOf().also {
            it[0] = invalidNumOfBytes.toByte()
        }

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(invalidMessage1)
            }
        )

        val zeroValueByte = 0x00
        val invalidMessage2 = validWireMessage.copyOf().also {
            it[0] = zeroValueByte.toByte()
        }

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(invalidMessage2)
            }
        )

        val outOfBoundsByteValue = 0xFF
        val invalidMessage3 = validWireMessage.copyOf().also {
            it[0] = outOfBoundsByteValue.toByte()
        }

        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(invalidMessage3)
            }
        )

        validWireMessage.copyOf().also {
            it[0] = outOfBoundsByteValue.toByte()
            val badByteArray = byteArrayOf(outOfBoundsByteValue.toByte())
            val invalidMessage4 = it + badByteArray
            assertFailsWith(
                exceptionClass = IllegalArgumentException::class,
                block = {
                    PlaintextMessage.fromBytes(invalidMessage4)
                }
            )
        }
    }

    @Test
    fun `PlaintextMessage resists zero length attack`()
    {
        val zeroLengthAttackMessage = byteArrayOf(0x01, 0x00)   // Decoded length 0
        assertFailsWith(
            exceptionClass = IllegalArgumentException::class,
            block = {
                PlaintextMessage.fromBytes(zeroLengthAttackMessage)
            }
        )
    }

 
    @Test
    fun `PlaintextMessage handles UTF-8 text`()
    {
        val originalText = "Hello 世界 🌍"
        val message = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            originalText.toByteArray(Charsets.UTF_8)
        )

        val serialized = message.toBytes()
        val deserialized = PlaintextMessage.fromBytes(serialized)
        val decodedText = String(deserialized.bytes, Charsets.UTF_8)

        assertEquals(originalText, decodedText)
    }

    // ========== SecureRatchetState Tests ===========

    @Test
    fun `Single use ratchet state can make a copy that survives destruction of original`() {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->
            val secureRatchetState = Ratchet.newRatchetState(
                aliceKeypair,
                bobKeypair.publicKey
            )

            var copyOfRatchetState: RatchetState? = null

            secureRatchetState.use { originalRatchetState ->
                copyOfRatchetState = originalRatchetState.deepCopy()
            }
            secureRatchetState.close()

            assert(copyOfRatchetState != null)
            assert(copyOfRatchetState?.rootKey?.bytes != null)
        }
    }

    // ========== RatchetState Tests ==========

    @Test
    fun `newRatchetState creates initial state with longterm keys only`()
    {
        val aliceSecureKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        aliceSecureKeypair.use { aliceKeypair ->
            bobKeypair.use { bobKeypair ->
                val singleUseRatchetState = Ratchet.newRatchetState(
                    aliceSecureKeypair,
                    bobKeypair.publicKey
                )

                singleUseRatchetState.use { state ->

                    // Initial state should have longterm keys and root key
                    assertNotNull(state.rootKey)
                    assertEquals(32, state.rootKey.bytes.size)
                    assertArrayEquals(aliceKeypair.publicKey.bytes, state.localLongtermKeypair.publicKey.bytes)
                    assertArrayEquals(aliceKeypair.privateKey.bytes, state.localLongtermKeypair.privateKey.bytes)
                    assertArrayEquals(bobKeypair.publicKey.bytes, state.remoteLongtermPublicKey.bytes)

                    // Ephemeral state should be null/default
                    assertEquals(0, state.messageNumber)
                    assertNull(state.chainKey)
                    assertNull(state.sharedKey)
                    assertNull(state.messageKey)
                    assertNull(state.localEphemeralKeypair)
                    assertNull(state.remoteEphemeralPublicKey)
                }
            }
        }
    }

    @Test
    fun `ratchetForSend generates ephemeral keys and derives chain`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            secureInitialState.use { state ->

                // Perform first ratchet with new key
                val result = Ratchet.ratchetForSend(secureInitialState)
                result.state.use { ratchetedState ->

                    // Should now have all ephemeral state
                    assertNotNull(ratchetedState.chainKey)
                    assertNotNull(ratchetedState.sharedKey)
                    assertNotNull(ratchetedState.messageKey)
                    assertNotNull(result.ephemeralPublicKeyToSend)

                    // Message number should increment
                    assertEquals(1, ratchetedState.messageNumber)

                    // Root key should be different from initial
                    assertFalse(state.rootKey.bytes.contentEquals(ratchetedState.rootKey.bytes))

                    // All keys should be 32 bytes
                    assertEquals(32, ratchetedState.chainKey!!.bytes.size)
                    assertEquals(32, ratchetedState.sharedKey!!.bytes.size)
                    assertEquals(32, ratchetedState.messageKey!!.bytes.size)
                    assertEquals(32, result.ephemeralPublicKeyToSend.bytes.size)
                }
            }
        }
    }

    @Test
    fun `ratchetForReceive generates state from sender ephemeral key`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->
            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            secureInitialState.use { initialState ->

                // Bob sends his ephemeral key
                val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

                bobEphemeralKeypair.use { bobEphemeralKeypair ->

                    Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey)
                        .use { ratchetedState ->

                            assertNotNull(ratchetedState.chainKey)
                            assertNotNull(ratchetedState.sharedKey)
                            assertNotNull(ratchetedState.messageKey)
                            assertNotNull(ratchetedState.remoteEphemeralPublicKey)

                            // Should now have all ephemeral state

                            // Message number should increment

                            assertEquals(1, ratchetedState.messageNumber)

                            // Root key should be different from initial
                            assertFalse(initialState.rootKey.bytes.contentEquals(ratchetedState.rootKey.bytes))

                            // All keys should be 32 bytes
                            assertEquals(32, ratchetedState.chainKey!!.bytes.size)
                            assertEquals(32, ratchetedState.sharedKey!!.bytes.size)
                            assertEquals(32, ratchetedState.messageKey!!.bytes.size)

                        }
                }
            }
        }
    }

    @Test
    fun `symmetricRatchet advances symmetric ratchet`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()
        val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            // Setup: create state with ephemeral keys
            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            val secureState1 = Ratchet.ratchetInternalWithIncomingKey(
                secureInitialState, aliceKeypair,
                remotePublicKey = bobEphemeralKeypair.publicKey
            )

            secureState1.use { state1 ->

                // Advance without new keys
                Ratchet.symmetricRatchetWithoutIncomingKey(secureState1).use { state2 ->

                    // Message number should increment
                    assertEquals(2, state2.messageNumber)

                    // Chain key and message key should change
                    assertFalse(state1.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
                    assertFalse(state1.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))

                    // Shared key and ephemeral keys should stay the same
                    assertArrayEquals(
                        state1.sharedKey!!.bytes,
                        state2.sharedKey!!.bytes
                    )
                    assertArrayEquals(
                        state1.localEphemeralKeypair?.publicKey?.bytes,
                        state2.localEphemeralKeypair?.publicKey?.bytes
                    )
                    assertArrayEquals(
                        state1.localEphemeralKeypair?.privateKey?.bytes,
                        state2.localEphemeralKeypair?.privateKey?.bytes
                    )
                    assertArrayEquals(
                        state1.remoteEphemeralPublicKey?.bytes,
                        state2.remoteEphemeralPublicKey?.bytes
                    )

                    // Root key should stay the same
                    assertArrayEquals(state1.rootKey.bytes, state2.rootKey.bytes)
                }
            }
        }
    }

    @Test
    fun `ratchetWithoutNewKey fails on initial state`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            // Should fail because there's no chain key yet
            try {
                Ratchet.symmetricRatchetWithoutIncomingKey(initialState)
                fail("Should have thrown IllegalArgumentException")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!.contains("chain key"))
            }
        }

    }

    @Test
    fun `multiple symmetric ratchets produce different keys`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

            bobEphemeralKeypair.use { bobEphemeralKeypair ->

                secureInitialState.use { initialState ->

                    Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey).use { state ->

                            val messageKeys = mutableListOf(state.messageKey!!.bytes)
                            var previousState = SecureRatchetState(state)

                            // Generate 5 more message keys
                            repeat(5)
                            {

                                Ratchet.symmetricRatchetWithoutIncomingKey(previousState).use { newState ->
                                    messageKeys.add(newState.messageKey!!.bytes)
                                    previousState = SecureRatchetState(newState)
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
    fun `encrypt and decrypt round trip`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            secureInitialState.use { initialState ->
                val bobEphemeralKeypair = Ratchet.generateMADHKeypair()
                bobEphemeralKeypair.use { bobEphemeralKeypair ->
                    Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey)
                        .use { state ->

                            val originalMessage = PlaintextMessage(
                                PlaintextMessageType.DATA,
                                "Hello, World!".toByteArray()
                            )

                            // Encrypt
                            val ciphertext = Ratchet.encrypt(state.messageKey!!, originalMessage)

                            // Decrypt with same key
                            val decryptedMessage = Ratchet.decrypt(state.messageKey!!, ciphertext)

                            assertEquals(originalMessage.type, decryptedMessage!!.type)
                            assertArrayEquals(originalMessage.bytes, decryptedMessage!!.bytes)
                        }
                }
            }
        }
    }

    @Test
    fun `encrypt produces different ciphertext each time`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

            bobEphemeralKeypair.use { bobEphemeralKeypair ->

                Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey)
                    .use { state ->

                        val message = PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Same message".toByteArray()
                        )

                        val ciphertext1 = Ratchet.encrypt(state.messageKey!!, message)
                        val ciphertext2 = Ratchet.encrypt(state.messageKey!!, message)

                        // Different nonces mean different ciphertexts
                        assertFalse(ciphertext1.nonce.bytes.contentEquals(ciphertext2.nonce.bytes))
                        assertFalse(ciphertext1.encrypted.contentEquals(ciphertext2.encrypted))
                    }
            }
        }
    }

    @Test
    fun `decrypt with wrong key fails`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val bobEphemeralKeypair = Ratchet.generateMADHKeypair()


            bobEphemeralKeypair.use { bobEphemeralKeypair ->

                Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey)
                    .use { state1 ->
                        val state2 = Ratchet.symmetricRatchetWithoutIncomingKey(SecureRatchetState(state1))

                        val message = PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Secret".toByteArray()
                        )

                        // Encrypt with state1's key
                        val ciphertext = Ratchet.encrypt(state1.messageKey!!, message)

                        // Try to decrypt with state2's key (should fail)
                        try {
                            state2.use { snapshotOfState2 ->
                                Ratchet.decrypt(snapshotOfState2.messageKey!!, ciphertext)
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
    fun `single party can encrypt and decrypt with consistent state`()
    {
        // This tests that a single party (Alice) can use the ratchet correctly
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

            bobEphemeralKeypair.use { bobEphemeralKeypair ->

                Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey)
                    .use { state ->

                        // Alice encrypts a message
                        val message = PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Hello!".toByteArray()
                        )
                        val ciphertext = Ratchet.encrypt(state.messageKey!!, message)

                        // Alice can decrypt with the same key
                        val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

                        assertEquals(PlaintextMessageType.DATA, decrypted!!.type)
                        assertEquals("Hello!", String(decrypted!!.bytes))
                    }
            }
        }
    }

    @Test
    fun `message exchange with explicit key coordination`()
    {
        // This demonstrates how the protocol would work with explicit key sharing
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->
            // Alice initializes and performs first ratchet
            val aliceSecureInitialState =
                Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

            bobEphemeralKeypair.use { bobEphemeralKeypair ->

                val aliceState1 = Ratchet.ratchetForReceive(aliceSecureInitialState, bobEphemeralKeypair.publicKey)
                aliceState1.use { aliceState1Snapshot ->

                    // Alice encrypts message 1
                    val message1 =
                        PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Message 1".toByteArray()
                        )
                    val ciphertext1 = Ratchet.encrypt(aliceState1Snapshot.messageKey!!, message1)

                    // Alice advances her ratchet for message 2
                    val aliceState2 = Ratchet.symmetricRatchetWithoutIncomingKey(aliceState1)
                    val message2 =
                        PlaintextMessage(
                            PlaintextMessageType.DATA,
                            "Message 2".toByteArray()
                        )

                    aliceState2.use { aliceState2Snapshot ->

                        val ciphertext2 =
                            Ratchet.encrypt(aliceState2Snapshot.messageKey!!, message2)

                        // Both messages can be decrypted with their respective keys
                        val decrypted1 =
                            Ratchet.decrypt(aliceState1Snapshot.messageKey!!, ciphertext1)
                        val decrypted2 =
                            Ratchet.decrypt(aliceState2Snapshot.messageKey!!, ciphertext2)

                        assertEquals("Message 1", String(decrypted1!!.bytes))
                        assertEquals("Message 2", String(decrypted2!!.bytes))

                        // Verify messages can't be decrypted with wrong keys
                        try {
                            Ratchet.decrypt(aliceState2Snapshot.messageKey!!, ciphertext1)
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
    fun `message keys evolve correctly through multiple ratchets`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            val secureInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            secureInitialState.use { initialState ->
                val bobEphemeralKeypair = Ratchet.generateMADHKeypair()

                bobEphemeralKeypair.use { bobEphemeralKeypair ->

                    Ratchet.ratchetForReceive(secureInitialState, bobEphemeralKeypair.publicKey)
                        .use { state ->

                            assertEquals(1, state.messageNumber)

                            var previousState = SecureRatchetState(state)

                            // Advance 10 times
                            repeat(10) { i ->
                                Ratchet.symmetricRatchetWithoutIncomingKey(previousState).use { newState ->
                                    assertEquals(i + 2, newState.messageNumber)
                                    assertNotNull(newState.messageKey)
                                    previousState = SecureRatchetState(newState)
                                }
                            }
                        }
                }
            }
        }
    }

    @Test
    fun `DH ratchet changes all keys`()
    {
        val aliceKeypair = Ratchet.generateMADHKeypair()
        val bobKeypair = Ratchet.generateMADHKeypair()
        val bobEphemeral1 = Ratchet.generateMADHKeypair()
        val bobEphemeral2 = Ratchet.generateMADHKeypair()

        bobKeypair.use { bobKeypair ->

            bobEphemeral1.use { bobEphemeral1 ->

                bobEphemeral2.use { bobEphemeral2 ->

                    val secureInitialState =
                        Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

                    secureInitialState.use { initialState ->

                        val state1 = Ratchet.ratchetForReceive(secureInitialState, bobEphemeral1.publicKey)
                        state1.use { state1Snapshot ->
                                Ratchet.ratchetForReceive(state1, bobEphemeral2.publicKey)
                                    .use { state2 ->

                                        // All ephemeral keys should be different
                                        assertFalse(state1Snapshot.rootKey.bytes.contentEquals(state2.rootKey.bytes))
                                        assertFalse(state1Snapshot.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
                                        assertFalse(state1Snapshot.sharedKey!!.bytes.contentEquals(state2.sharedKey!!.bytes))
                                        assertFalse(state1Snapshot.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))
                                        assertNotEquals(
                                            state1Snapshot.remoteEphemeralPublicKey,
                                            state2.remoteEphemeralPublicKey
                                        )
                                    }
                            }
                    }
                }
            }
        }
    }
}