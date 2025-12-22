package org.operatorfoundation.ratchet

import org.junit.Test
import org.junit.Assert.*
import org.operatorfoundation.madh.MADH

class RatchetIntegrationTest
{
    @Test
    fun `newRatchetState creates valid initial state`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val state = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        // Initial state has only longterm keys and root key
        assertNotNull(state.rootKey)
        assertEquals(0, state.messageNumber)

        // Ephemeral keys are not yet generated
        assertNull(state.chainKey)
        assertNull(state.sharedKey)
        assertNull(state.messageKey)
        assertNull(state.localEphemeralKeypair)
        assertNull(state.remoteEphemeralPublicKey)
    }

    @Test
    fun `both parties derive same initial root key`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val aliceState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val bobState = Ratchet.newRatchetState(
            bobKeypair,
            aliceKeypair.publicKey
        )

        // Both should derive the same root key (ECDH is commutative)
        assertArrayEquals(aliceState.rootKey.bytes, bobState.rootKey.bytes)
    }

    @Test
    fun `ratchetForSend performs DH ratchet step`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val result = Ratchet.ratchetForSend(initialState)
        val newState = result.state

        // All keys should be created after DH ratchet
        assertNotNull(newState.chainKey)
        assertNotNull(newState.sharedKey)
        assertNotNull(newState.messageKey)
        assertNotNull(result.ephemeralPublicKeyToSend)

        // Root key should change
        assertFalse(initialState.rootKey.bytes.contentEquals(newState.rootKey.bytes))

        // Message number should increment
        assertEquals(1, newState.messageNumber)
    }

    @Test
    fun `ratchetForReceive performs DH ratchet step`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val senderEphemeralKey = MADH.generateKeypair().publicKey
        val newState = Ratchet.ratchetForReceive(initialState, senderEphemeralKey)

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

    @Test
    fun `ratchetWithoutNewKey performs symmetric ratchet step`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        // Need to do DH ratchet first to get ephemeral keys
        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val senderEphemeralKey = MADH.generateKeypair().publicKey
        val state1 = Ratchet.ratchetForReceive(initialState, senderEphemeralKey)

        val state2 = Ratchet.symmetricRatchet(state1)

        // Chain and message keys should change (symmetric ratchet)
        assertFalse(state1.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
        assertFalse(state1.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))

        // Root key, shared key, and ephemeral keys should remain unchanged
        assertArrayEquals(state1.rootKey.bytes, state2.rootKey.bytes)
        assertArrayEquals(state1.sharedKey!!.bytes, state2.sharedKey!!.bytes)
        assertEquals(state1.localEphemeralKeypair, state2.localEphemeralKeypair)
        assertEquals(state1.remoteEphemeralPublicKey, state2.remoteEphemeralPublicKey)

        // Message number should increment
        assertEquals(2, state2.messageNumber)
    }

    @Test
    fun `encrypt and decrypt round trip preserves message`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        // Need to perform DH ratchet first to get a message key
        val result = Ratchet.ratchetForSend(initialState)
        val state = result.state

        val originalMessage = PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "Hello, World!".toByteArray()
        )

        val ciphertext = Ratchet.encrypt(state.messageKey!!, originalMessage)
        val decryptedMessage = Ratchet.decrypt(state.messageKey!!, ciphertext)

        assertEquals(originalMessage.type, decryptedMessage.type)
        assertArrayEquals(originalMessage.bytes, decryptedMessage.bytes)
    }

    @Test
    fun `multiple messages can be sent with symmetric ratcheting`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        // Perform initial DH ratchet
        val result = Ratchet.ratchetForSend(initialState)
        var state = result.state

        val messages = listOf("First", "Second", "Third")

        for (messageText in messages)
        {
            val plaintext = PlaintextMessage(
                PlaintextMessageType.UNCOMPRESSED_TEXT,
                messageText.toByteArray()
            )

            val ciphertext = Ratchet.encrypt(state.messageKey!!, plaintext)
            val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

            assertArrayEquals(plaintext.bytes, decrypted.bytes)

            // Advance ratchet for next message
            state = Ratchet.symmetricRatchet(state)
        }
    }

    @Test
    fun `Alice can send multiple messages to herself`()
    {
        // This test demonstrates single-party usage
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val aliceInitialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val result = Ratchet.ratchetForSend(aliceInitialState)
        var aliceState = result.state

        // Alice sends first message
        val message1 = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            "Hello Bob".toByteArray()
        )
        val ciphertext1 = Ratchet.encrypt(aliceState.messageKey!!, message1)
        val decrypted1 = Ratchet.decrypt(aliceState.messageKey!!, ciphertext1)
        assertArrayEquals(message1.bytes, decrypted1.bytes)

        // Alice advances ratchet and sends second message
        aliceState = Ratchet.symmetricRatchet(aliceState)

        val message2 = PlaintextMessage(
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            "Hello again".toByteArray()
        )
        val ciphertext2 = Ratchet.encrypt(aliceState.messageKey!!, message2)
        val decrypted2 = Ratchet.decrypt(aliceState.messageKey!!, ciphertext2)
        assertArrayEquals(message2.bytes, decrypted2.bytes)
    }

    @Test
    fun `DH ratchet provides forward secrecy`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        // Perform first DH ratchet with ephemeral keys
        val result1 = Ratchet.ratchetForSend(initialState)
        val state1 = result1.state

        // Perform second DH ratchet with new ephemeral keys
        val result2 = Ratchet.ratchetForSend(state1)
        val state2 = result2.state

        // All keys should be completely different (forward secrecy)
        assertFalse(state1.rootKey.bytes.contentEquals(state2.rootKey.bytes))
        assertFalse(state1.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes))
        assertFalse(state1.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes))
        assertFalse(state1.sharedKey!!.bytes.contentEquals(state2.sharedKey!!.bytes))

        // The ephemeral keys should be different
        assertFalse(result1.ephemeralPublicKeyToSend.bytes.contentEquals(result2.ephemeralPublicKeyToSend.bytes))
    }

    @Test
    fun `same plaintext with different keys produces different ciphertexts`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val result = Ratchet.ratchetForSend(initialState)
        var state = result.state

        val message = PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = "Same message".toByteArray()
        )

        val ciphertext1 = Ratchet.encrypt(state.messageKey!!, message)

        // Advance ratchet to get new message key
        state = Ratchet.symmetricRatchet(state)

        val ciphertext2 = Ratchet.encrypt(state.messageKey!!, message)

        // Same plaintext with different keys should produce different ciphertexts
        assertFalse(ciphertext1.encrypted.contentEquals(ciphertext2.encrypted))
        assertFalse(ciphertext1.nonce.bytes.contentEquals(ciphertext2.nonce.bytes))
    }

    @Test
    fun `different message types can be encrypted and decrypted`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val result = Ratchet.ratchetForSend(initialState)
        val state = result.state

        val messageTypes = listOf(
            PlaintextMessageType.HANDSHAKE,
            PlaintextMessageType.RATCHET,
            PlaintextMessageType.ERROR,
            PlaintextMessageType.COMPRESSED_TEXT,
            PlaintextMessageType.UNCOMPRESSED_TEXT,
            PlaintextMessageType.DATA
        )

        for (messageType in messageTypes)
        {
            val message = PlaintextMessage(messageType, "test".toByteArray())
            val ciphertext = Ratchet.encrypt(state.messageKey!!, message)
            val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

            assertEquals(messageType, decrypted.type)
            assertArrayEquals("test".toByteArray(), decrypted.bytes)
        }
    }

    @Test
    fun `message numbers increment correctly through ratcheting`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        assertEquals(0, initialState.messageNumber)

        // DH ratchet increments to 1
        val result = Ratchet.ratchetForSend(initialState)
        var state = result.state
        assertEquals(1, state.messageNumber)

        // Symmetric ratchets increment by 1 each
        for (i in 2..10)
        {
            state = Ratchet.symmetricRatchet(state)
            assertEquals(i, state.messageNumber)
        }
    }

    @Test
    fun `cannot decrypt with wrong key`()
    {
        val aliceKeypair = MADH.generateKeypair()
        val bobKeypair = MADH.generateKeypair()

        val initialState = Ratchet.newRatchetState(
            aliceKeypair,
            bobKeypair.publicKey
        )

        val result = Ratchet.ratchetForSend(initialState)
        val state1 = result.state
        val state2 = Ratchet.symmetricRatchet(state1)

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
}