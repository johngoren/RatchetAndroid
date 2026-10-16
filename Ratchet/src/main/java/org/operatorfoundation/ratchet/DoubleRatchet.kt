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
import org.operatorfoundation.ratchet.models.keys.secure.SecureKeyPair
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

class RedoHandshakeException(message: String = "Something went wrong. You need to renegotiate the handshake"): Exception(message)

object DoubleRatchet
{
    const val NUM_BYTES_IN_KEY = 32
    const val NUM_BYTES_IN_SESSION_NONCE = 16   // TODO: Decide on length and note down justification

    class RatchetSendResult(
        val state: SecureRatchetState,
        val newEphemeralPublicKey: Curve25519PublicKey
    )

    // ========== Creating a new ratchet state ==========

    /**
     * Creates a new ratchet state from long-term keys
     * This initializes the double ratchet algorithm.
     *
     * According to the spec:
     * R_0 = ECDH(priv_a0, k_b0)
     *
     * @param initialLocalKeypair The user's initial ephemeral keypair, set up earlier via handshake.
     * @param initialRemotePublicKey The remote party's first ephemeral public key
     * @return The initial ratchet state
     */
    fun initRatchetState(
        initialLocalKeypair: SecureKeyPair,
        initialRemotePublicKey: Curve25519PublicKey,
        sessionId: ByteArray = ByteArray(16) // TODO: Require actual nonce and make sure it's not repeatable from OOB
    ): SecureRatchetState
    {
        var newRatchetState: SecureRatchetState? = null

        val copyOfInitialLocalKeypair = initialLocalKeypair.copyOf()
        val copyOfInitialRemotePublicKey = Curve25519PublicKey(initialRemotePublicKey.bytes.copyOf())
        var copyOfInitialLocalPrivateKey: PrivateKey? = null
        val copyOfSessionId = sessionId.copyOf()

        var hkdfOutput: ByteArray? = null
        var initialSharedSecret: Secret? = null
        var newState: RatchetState? = null

        return try {
            require(copyOfSessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Invalid length of session nonce" }

            copyOfInitialLocalKeypair.use { localKeypairPeek ->

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                copyOfInitialLocalPrivateKey = PrivateKey(localKeypairPeek.privateKey.bytes)
                initialSharedSecret = ECDH.perform(copyOfInitialLocalPrivateKey, copyOfInitialRemotePublicKey)

                // New derivation step to make sure we don't use secret key material directly
                hkdfOutput = HKDF.forRootKeyMaterial(
                    initialSharedSecret,
                    ContextField.getInfo(ContextField.RootKey.INFOPREFIX, copyOfSessionId.copyOf())
                )

                // Return initial state with defaults for optional fields
                newState = RatchetState(
                    rootKey = RootKey.fromHKDF(hkdfOutput.copyOf()),
                    sessionId = copyOfSessionId.copyOf(),
                    localEphemeralKeypair = initialLocalKeypair.copyOf(),
                    lastKnownRemotePublicEphemeralKey = initialRemotePublicKey.copy()
                )
                newRatchetState = SecureRatchetState(newState)
            }
            newRatchetState!!
        }
        catch(e: Exception) {
            newState?.close()
            throw RedoHandshakeException(e.message ?: "Something went wrong in initialization")
        }
        finally {
//            copyOfInitialLocalKeypair.close()
//            copyOfInitialRemotePublicKey.bytes.fill(0)
//            copyOfInitialLocalPrivateKey?.close()
//            copyOfSessionId.fill(0)
//            initialSharedSecret?.close()
//            hkdfOutput?.fill(0)
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

    // TODO: Where to update outgoing counter?
    // TODO: Consistent copying behavior
    fun ratchetForSend(oldState: SecureRatchetState): RatchetSendResult
    {
        var result: RatchetSendResult? = null

        val newEphemeralKeypair = generateEphemeralKeypair()
        var copyOfRemoteKeyBytes: ByteArray? = null

        return try {
            oldState.use { oldStatePeek ->
                copyOfRemoteKeyBytes = oldStatePeek.lastKnownRemotePublicEphemeralKey?.bytes?.copyOf()
                require(copyOfRemoteKeyBytes != null) { throw RedoHandshakeException("No remote public key to work with")}

                DHRatchet.perform(
                    oldState = oldState,
                    localEphemeralKeypair = newEphemeralKeypair,
                    remotePublicKey = Curve25519PublicKey(copyOfRemoteKeyBytes!!)
                )
                .use { newState ->
                    val newRatchetState = SecureRatchetState(newState)
                    result = RatchetSendResult(
                        newRatchetState,
                        newEphemeralKeypair.publicKey,
                    )
                }
            }
        result ?: throw RedoHandshakeException("Trouble creating ratchet result")
        }
        catch(e: Exception) {
            throw RedoHandshakeException()
        }
        finally {
            newEphemeralKeypair.close()
            copyOfRemoteKeyBytes?.fill(0)
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
                require(oldStatePeek.localEphemeralKeypair != null) { throw RedoHandshakeException("No local ephemeral keys available") }
                localEphemeralKeypair = oldStatePeek.localEphemeralKeypair

                incomingCounter?.also {
                    validateCounter(incomingCounter, oldStatePeek.counterLastReceivedKeyNum)
                }

                // TODO: The DHRatchet receives either an outgoing or incoming counter, +1 from the last one

                val resultingRatchetState = DHRatchet.perform(
                    oldState = oldStateSecure,
                    localEphemeralKeypair = localEphemeralKeypair,
                    remotePublicKey = incomingEphemeralPublicKey,
                    counter = incomingCounter
                )

                newRatchetState = resultingRatchetState
            }
            require(newRatchetState != null) { throw RedoHandshakeException("Null ratchet state") }
            newRatchetState
        } catch(e: Exception) {
            throw RedoHandshakeException(e.message ?: "Something went wrong while receiving a message")
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


    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): SecureKeyPair {
        return SecureKeyPair(MADH.generateKeypair())
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
