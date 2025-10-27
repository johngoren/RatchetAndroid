package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.madh.MADH

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

    // ========== RatchetState Tests ==========

    @Test
    fun `newRatchetState creates initial state with longterm keys only`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val state = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        // Initial state should have longterm keys and root key
        assertNotNull(state.rootKey)
        assertEquals(32, state.rootKey.bytes.size)
        assertEquals(aliceKeypair, state.localLongtermKeypair)
        assertEquals(bobKeypair.publicKey, state.remoteLongtermPublicKey)

        // Ephemeral state should be null/default
        assertEquals(0, state.messageNumber)
        assertNull(state.chainKey)
        assertNull(state.sharedKey)
        assertNull(state.messageKey)
        assertNull(state.localEphemeralKeypair)
        assertNull(state.remoteEphemeralPublicKey)
    }

    @Test
    fun `ratchetWithNewKey generates ephemeral keys and derives chain`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

        // Perform first ratchet with new key
        val bobEphemeralKeypair = MADH.generateKeypair()
        val ratchetedState = Ratchet.ratchetWithNewKey(
            initialState,
            bobEphemeralKeypair.publicKey
        )

        // Should now have all ephemeral state
        assertNotNull(ratchetedState.chainKey)
        assertNotNull(ratchetedState.sharedKey)
        assertNotNull(ratchetedState.messageKey)
        assertNotNull(ratchetedState.localEphemeralKeypair)
        assertNotNull(ratchetedState.remoteEphemeralPublicKey)

        // Message number should increment
        assertEquals(1, ratchetedState.messageNumber)

        // Root key should be different from initial
        assertFalse(initialState.rootKey.bytes.contentEquals(ratchetedState.rootKey.bytes))

        // All keys should be 32 bytes
        assertEquals(32, ratchetedState.chainKey!!.bytes.size)
        assertEquals(32, ratchetedState.sharedKey!!.bytes.size)
        assertEquals(32, ratchetedState.messageKey!!.bytes.size)
    }

    @Test
    fun `ratchetWithoutNewKey advances symmetric ratchet`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        // Setup: create state with ephemeral keys
        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val state1 = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)

        // Advance without new keys
        val state2 = Ratchet.ratchetWithoutNewKey(state1)

        // Message number should increment
        assertEquals(2, state2.messageNumber)

        // Chain key and message key should change
        assertFalse(state1.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
        assertFalse(state1.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))

        // Shared key and ephemeral keys should stay the same
        assertArrayEquals(state1.sharedKey!!.bytes, state2.sharedKey!!.bytes)
        assertEquals(state1.localEphemeralKeypair, state2.localEphemeralKeypair)
        assertEquals(state1.remoteEphemeralPublicKey, state2.remoteEphemeralPublicKey)

        // Root key should stay the same
        assertArrayEquals(state1.rootKey.bytes, state2.rootKey.bytes)
    }

    @Test
    fun `ratchetWithoutNewKey fails on initial state`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

        // Should fail because there's no chain key yet
        try
        {
            Ratchet.ratchetWithoutNewKey(initialState)
            fail("Should have thrown IllegalArgumentException")
        }
        catch (e: IllegalArgumentException)
        {
            assertTrue(e.message!!.contains("chain key"))
        }
    }

    @Test
    fun `multiple symmetric ratchets produce different keys`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        var state = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)

        val messageKeys = mutableListOf(state.messageKey!!.bytes)

        // Generate 5 more message keys
        repeat(5)
        {
            state = Ratchet.ratchetWithoutNewKey(state)
            messageKeys.add(state.messageKey!!.bytes)
        }

        // All message keys should be unique
        for (i in messageKeys.indices)
        {
            for (j in i + 1 until messageKeys.size)
            {
                assertFalse(
                    "Message keys $i and $j should be different",
                    messageKeys[i].contentEquals(messageKeys[j])
                )
            }
        }
    }

    // ========== Encryption/Decryption Tests ==========

    @Test
    fun `encrypt and decrypt round trip`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val state = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)

        val originalMessage = PlaintextMessage(
            PlaintextMessageType.DATA,
            "Hello, World!".toByteArray()
        )

        // Encrypt
        val ciphertext = Ratchet.encrypt(state.messageKey!!, originalMessage)

        // Decrypt with same key
        val decryptedMessage = Ratchet.decrypt(state.messageKey!!, ciphertext)

        assertEquals(originalMessage.type, decryptedMessage.type)
        assertArrayEquals(originalMessage.bytes, decryptedMessage.bytes)
    }

    @Test
    fun `encrypt produces different ciphertext each time`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val state = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)

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

    @Test
    fun `decrypt with wrong key fails`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val state1 = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)
        val state2 = Ratchet.ratchetWithoutNewKey(state1)

        val message = PlaintextMessage(
            PlaintextMessageType.DATA,
            "Secret".toByteArray()
        )

        // Encrypt with state1's key
        val ciphertext = Ratchet.encrypt(state1.messageKey!!, message)

        // Try to decrypt with state2's key (should fail)
        try
        {
            Ratchet.decrypt(state2.messageKey!!, ciphertext)
            fail("Should have thrown SecurityException")
        }
        catch (e: SecurityException)
        {
            assertTrue(e.message!!.contains("Authentication"))
        }
    }

    // ========== Protocol Flow Tests ==========

    @Test
    fun `single party can encrypt and decrypt with consistent state`()
    {
        // This tests that a single party (Alice) can use the ratchet correctly
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val state = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)

        // Alice encrypts a message
        val message = PlaintextMessage(
            PlaintextMessageType.DATA,
            "Hello!".toByteArray()
        )
        val ciphertext = Ratchet.encrypt(state.messageKey!!, message)

        // Alice can decrypt with the same key
        val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

        assertEquals(PlaintextMessageType.DATA, decrypted.type)
        assertEquals("Hello!", String(decrypted.bytes))
    }

    @Test
    fun `message exchange with explicit key coordination`()
    {
        // This demonstrates how the protocol would work with explicit key sharing
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        // Alice initializes and performs first ratchet
        val aliceInitialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val bobEphemeralKeypair = MADH.generateKeypair()
        val aliceState1 = Ratchet.ratchetWithNewKey(aliceInitialState, bobEphemeralKeypair.publicKey)

        // Alice encrypts message 1
        val message1 = PlaintextMessage(PlaintextMessageType.DATA, "Message 1".toByteArray())
        val ciphertext1 = Ratchet.encrypt(aliceState1.messageKey!!, message1)

        // Alice advances her ratchet for message 2
        val aliceState2 = Ratchet.ratchetWithoutNewKey(aliceState1)
        val message2 = PlaintextMessage(PlaintextMessageType.DATA, "Message 2".toByteArray())
        val ciphertext2 = Ratchet.encrypt(aliceState2.messageKey!!, message2)

        // Both messages can be decrypted with their respective keys
        val decrypted1 = Ratchet.decrypt(aliceState1.messageKey!!, ciphertext1)
        val decrypted2 = Ratchet.decrypt(aliceState2.messageKey!!, ciphertext2)

        assertEquals("Message 1", String(decrypted1.bytes))
        assertEquals("Message 2", String(decrypted2.bytes))

        // Verify messages can't be decrypted with wrong keys
        try {
            Ratchet.decrypt(aliceState2.messageKey!!, ciphertext1)
            fail("Should not decrypt with wrong key")
        } catch (e: SecurityException) {
            // Expected - demonstrates forward secrecy
        }
    }

    @Test
    fun `message keys evolve correctly through multiple ratchets`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeralKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        var state = Ratchet.ratchetWithNewKey(initialState, bobEphemeralKeypair.publicKey)

        assertEquals(1, state.messageNumber)

        // Advance 10 times
        repeat(10) { i ->
            state = Ratchet.ratchetWithoutNewKey(state)
            assertEquals(i + 2, state.messageNumber)
            assertNotNull(state.messageKey)
        }
    }

    @Test
    fun `DH ratchet changes all keys`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()
        val bobEphemeral1 = MADH.generateKeypair()
        val bobEphemeral2 = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
        val state1 = Ratchet.ratchetWithNewKey(initialState, bobEphemeral1.publicKey)
        val state2 = Ratchet.ratchetWithNewKey(state1, bobEphemeral2.publicKey)

        // All ephemeral keys should be different
        assertFalse(state1.rootKey.bytes.contentEquals(state2.rootKey.bytes))
        assertFalse(state1.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
        assertFalse(state1.sharedKey!!.bytes.contentEquals(state2.sharedKey!!.bytes))
        assertFalse(state1.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))
        assertNotEquals(state1.localEphemeralKeypair, state2.localEphemeralKeypair)
        assertNotEquals(state1.remoteEphemeralPublicKey, state2.remoteEphemeralPublicKey)
    }
}