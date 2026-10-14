package org.operatorfoundation.ratchet

import org.operatorfoundation.aes.AesGcmKey
import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeyPair
import org.operatorfoundation.ratchet.ratchets.DHRatchet
import org.operatorfoundation.ratchet.ratchets.SymmetricRatchet
import org.operatorfoundation.ratchet.utils.ContextField
import org.operatorfoundation.ratchet.utils.ECDH
import org.operatorfoundation.ratchet.utils.HKDF

/**
 * Main API for the Double Ratchet algorithm.
 *
 * The Double Ratchet provides forward secrecy and break-in recovery for
 * asynchronous messaging by combining a Diffie-Hellman ratchet with a
 * symmetric key ratchet.
 *
 *
 */

class MustReestablishHandshakeException: Exception("The session has become invalid. Please redo the handshake.")

object DoubleRatchet
{
    const val NUM_BYTES_IN_KEY = 32
    const val NUM_BYTES_IN_SESSION_NONCE = 16   // TODO: Decide on length and note down justification

    class RatchetSendResult(
        val state: SecureRatchetState,
        val outgoingEphemeralPublicKey: Curve25519PublicKey,
    )

    // ========== Creating a new ratchet state ==========

    /**
     * Creates a new ratchet state from long-term keys
     * This initializes the double ratchet algorithm.
     *
     * According to the spec:
     * R_0 = ECDH(priv_a0, k_b0)
     *
     * @param localLongtermKeypair The local party's long-term key pair
     * @param remoteLongtermPublicKey The remote party's long-term public key
     * @return The initial ratchet state
     */
    fun initRatchetState(
        localLongtermKeypair: SecureKeyPair,
        remoteLongtermPublicKey: Curve25519PublicKey,
        sessionId: ByteArray = ByteArray(16) // TODO: Require actual nonce
    ): SecureRatchetState
    {
        var newRatchetState: SecureRatchetState? = null

        val copyOfLongtermKeypair = localLongtermKeypair.copyOf()
        val copyOfRemoteLongtermPublicKey = Curve25519PublicKey(remoteLongtermPublicKey.bytes.copyOf())
        var copyOfLocalPrivateKey: PrivateKey? = null
        val copyOfSessionId = sessionId.copyOf()
        var hkdfOutput: ByteArray? = null
        var sharedSecret: Secret? = null
        var newState: RatchetState? = null

        return try {
            require(copyOfSessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Invalid length of sessionID" }

            copyOfLongtermKeypair.use { localKeypairPeek ->

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                copyOfLocalPrivateKey = PrivateKey(localKeypairPeek.privateKey.bytes)
                sharedSecret = ECDH.perform(copyOfLocalPrivateKey, copyOfRemoteLongtermPublicKey)

                // TODO: Put down a note here if necessary, is this a new derivation step?
                hkdfOutput = HKDF.forRootKeyMaterial(
                    sharedSecret,
                    ContextField.getInfo(ContextField.RootKey.INFOPREFIX, copyOfSessionId.copyOf())
                )

                // Return initial state with defaults for optional fields
                newState = RatchetState(
                    localLongtermKeypair = copyOfLongtermKeypair,
                    remoteLongtermPublicKey = copyOfRemoteLongtermPublicKey,
                    rootKey = RootKey.fromHKDF(hkdfOutput),
                    sessionId = copyOfSessionId.copyOf()
                )
                newRatchetState = SecureRatchetState(newState)
            }
            newRatchetState!!
        }
        catch(e: Exception) {
            newState?.close()
            invalidateAllState(localLongtermKeypair, remoteLongtermPublicKey)
            error(ERROR_MESSAGE_NEW_HANDSHAKE_REQUIRED)
        }
        finally {
            copyOfLongtermKeypair.close()
            copyOfRemoteLongtermPublicKey.bytes.fill(0)
            copyOfLocalPrivateKey?.close()
            copyOfSessionId.fill(0)
            sharedSecret?.close()
            hkdfOutput?.fill(0)
        }
    }

    // ========== Sending and receiving ==========

    /**
     * Ratchet for sending a message.
     * Generates a new ephemeral keypair and uses the current remote public key.
     *
     * @param oldState The current ratchet state
     * @return Result containing the new state and the ephemeral public key to send
     */
    fun ratchetForSend(oldState: SecureRatchetState): RatchetSendResult
    {
        var result: RatchetSendResult? = null

        val newEphemeralKeypair = generateEphemeralKeypair()
        var remoteKey: Curve25519PublicKey? = null

        return try {
            oldState.use { oldState ->
                remoteKey = oldState.remoteEphemeralPublicKey ?: MADH.generateKeypair().publicKey   // TODO: And bind to counter.

                DHRatchet.perform(
                    oldState=SecureRatchetState(oldState),
                    localEphemeralKeypair = newEphemeralKeypair.copyOf(),
                    incomingPublicKey = Curve25519PublicKey(remoteKey.bytes.copyOf()))
                .use { newState ->
                    val newOutgoingCounter = oldState.counterLastSentKeyNum + 1
                    newState.counterLastSentKeyNum = newOutgoingCounter

                    val newRatchetState = SecureRatchetState(newState)
                    result = RatchetSendResult(
                        newRatchetState,
                        newEphemeralKeypair.publicKey,
                    )
                }
            }
        result ?: throw Exception("Null ratchet send result")
        }
        catch(e: Exception) {
            throw e             // TODO: Granular error handling
        }
        finally {
            newEphemeralKeypair.close()
            remoteKey?.bytes?.fill(0)
        }
    }

    /**
     * Ratchet for receiving a message.
     * Uses the current local keypair with the sender's new ephemeral public key.
     *
     * @param oldState The current ratchet state
     * @param incomingEphemeralPublicKey The ephemeral public key received from the sender
     * @param incomingCounter The message counter number that was received from the sender
     * @return The updated ratchet state
     */
    fun ratchetForReceive(oldStateSecure: SecureRatchetState, incomingEphemeralPublicKey: Curve25519PublicKey, incomingCounter: Int? = null): SecureRatchetState {
        var newRatchetState: SecureRatchetState? = null
        var localEphemeralKeypair: SecureKeyPair? = null

        return try {
            oldStateSecure.use { oldStatePeek ->
                localEphemeralKeypair = oldStatePeek.localEphemeralKeypair ?: SecureKeyPair(MADH.generateKeypair()) // TODO: And bind to counter. Can do all in one function

                // TODO: It shouldn't be nullable
                incomingCounter?.also {
                    validateCounter(incomingCounter, oldStatePeek.counterLastReceivedKeyNum)
                }

                val resultingRatchetState = DHRatchet.perform(
                    oldState = oldStateSecure,
                    localEphemeralKeypair = localEphemeralKeypair,
                    incomingPublicKey = incomingEphemeralPublicKey,
                    incomingCounter = incomingCounter
                )

                newRatchetState = resultingRatchetState
            }
            require(newRatchetState != null) { "Null ratchet state" }
            newRatchetState
        } catch(e: Exception) {
            throw e     // TODO: Catch errors
        }
        finally {
            localEphemeralKeypair?.close()
        }
    }

    private fun validateCounter(incomingCounter: Int, lastReceivedCounterNum: Int) {
        if (incomingCounter <= lastReceivedCounterNum) {
            throw SecurityException("ECDHE counter failed to increment")
        }
    }

    /**
     * Symmetric Ratchet
     *
     * Starting points for use by client application
     */

    fun symmetricRatchet(oldState: SecureRatchetState): SecureRatchetState {
        return SymmetricRatchet.perform(oldState)
    }

    fun dhRatchet(
        oldState: SecureRatchetState,
        localEphemeralKeypair: SecureKeyPair,          // TODO: Safe to make this non-nullable?
        incomingPublicKey: Curve25519PublicKey        // Incoming ephemeral PK
    ): SecureRatchetState {

        return DHRatchet.perform(
            oldState,
            localEphemeralKeypair,
            incomingPublicKey
        )
    }


    // ========== Encrypting and decrypting ==========

    /**
     * Encrypts a plaintext message using the message key.
     * Uses AES-GCM for authenticated encryption.
     *
     * @param key The message key to use for encryption
     * @param plaintext The plaintext message to encrypt
     * @return The ciphertext
     */
    fun encrypt(key: MessageKey, plaintext: PlaintextMessage): Ciphertext
    {
        var copyOfPlaintextBytes: ByteArray? = null
        var aesKey: AesGcmKey? = null

        return try {
            // Serialize the plaintext message to bytes
            copyOfPlaintextBytes = plaintext.toBytes()

            // Create AES-GCM key from the message key
            aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes.copyOf())

            // Create cipher and encrypt
            val cipher = org.operatorfoundation.aes.AesCipher()
            return cipher.encrypt(aesKey, copyOfPlaintextBytes)
        }
        catch(e: Exception) {
            throw e // TODO: Error handling
        }
        finally {
            copyOfPlaintextBytes?.fill(0)
            aesKey?.bytes?.fill(0)
        }
    }

    /**
     * Decrypts a ciphertext message using the message key.
     * Uses AES-GCM for authenticated decryption.
     *
     * @param key The message key to use for decryption
     * @param ciphertext The ciphertext to decrypt
     * @return The decrypted plaintext message
     */
    fun decrypt(key: MessageKey, ciphertext: Ciphertext): PlaintextMessage?
    {
        var aesKey: AesGcmKey? = null
        var decryptedBytes: ByteArray? = null

        return try {

            // Create AES-GCM key from the message key
            aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes.copyOf())

            // Create cipher and decrypt
            val cipher = org.operatorfoundation.aes.AesCipher()
            decryptedBytes = cipher.decrypt(aesKey, ciphertext)

            // Deserialize the plaintext message
            PlaintextMessage.fromBytes(decryptedBytes.copyOf())
        }
        catch(e: IllegalArgumentException) {
            return null
        }
        finally {
            aesKey?.bytes?.fill(0)
            decryptedBytes?.fill(0)
        }
    }




    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): SecureKeyPair {
        return SecureKeyPair(MADH.generateKeypair())
    }

    private fun invalidateAllState(localLongtermKeypair: SecureKeyPair, remotePublicKey: Curve25519PublicKey) {
        localLongtermKeypair.close()
        remotePublicKey.bytes.fill(0)
    }

    val RADIX_FOR_COUNTER_ENCODING = 16



    private fun decodeHexBytesToNumber(bytes: ByteArray): Int? {
        try {
            return bytes
                .toString(Charsets.UTF_8)
                .toInt(RADIX_FOR_COUNTER_ENCODING)
        }
        catch(e: Exception) {
            throw IllegalArgumentException("Could not decode into hex")
        }
    }

    const val ERROR_MESSAGE_NEW_HANDSHAKE_REQUIRED = "Ratchet error. New handshake required."

}
