package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair
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

object Ratchet
{
    const val NUM_BYTES_IN_KEY = 32
    const val NUM_BYTES_IN_SESSION_NONCE = 16   // TODO: Decide on length and note down justification

    class RatchetSendResult(
        val state: RatchetState,
        val newEphemeralPublicKey: EphemeralPublicKey
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
        initialLocalKeypair: EphemeralKeypair,
        initialRemotePublicKey: EphemeralPublicKey,
        sessionId: ByteArray = ByteArray(16) // TODO: Require actual nonce and make sure it's not repeatable from OOB
    ): RatchetState
    {
        var copyOfRemotePublicKey: EphemeralPublicKey? = null

        copyOfRemotePublicKey = EphemeralPublicKey(initialRemotePublicKey.copyBytes())

        val copyOfInitialLocalKeypair = initialLocalKeypair.copyOf()
        var copyOfInitialLocalPrivateKey: PrivateKey? = null
        val copyOfSessionId = sessionId.copyOf()

        var hkdfOutput: ByteArray? = null
        var initialSharedSecret: Secret? = null
        var newState: RatchetState? = null

        return try {
            require(copyOfSessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Invalid length of session nonce" }

            copyOfInitialLocalKeypair.consume { localPublicKey, localPrivateKey ->

                localPrivateKey.consume {
                    copyOfInitialLocalPrivateKey = PrivateKey(it)
                }
                require(copyOfInitialLocalPrivateKey != null)

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                initialSharedSecret = ECDH.perform(copyOfInitialLocalPrivateKey, copyOfRemotePublicKey)

                // New derivation step to make sure we don't use secret key material directly
                hkdfOutput = HKDF.forRootKeyMaterial(
                    initialSharedSecret,
                    ContextField.getInfo(ContextField.RootKey.INFOPREFIX, copyOfSessionId.copyOf())
                )

                // Return initial state with defaults for optional fields
                newState = RatchetState(
                    rootKey = RootKey.fromHKDF(hkdfOutput.copyOf()),
                    sessionId = copyOfSessionId.copyOf(),
                    localEphemeralKeypair = copyOfInitialLocalKeypair.copyOf(),
                    remoteEphemeralPublicKey = EphemeralPublicKey(copyOfRemotePublicKey.copyBytes())
                )
            }
            newState ?: throw RedoHandshakeException("Something went wrong in initialization")
        }
        catch(e: Exception) {
            throw RedoHandshakeException(e.message ?: "Something went wrong in initialization")
        }
        finally {
            copyOfInitialLocalKeypair.close()
            copyOfInitialLocalPrivateKey?.close()
            copyOfSessionId.fill(0)
            initialSharedSecret?.close()
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

    // TODO: Where to update outgoing counter?
    fun ratchetForSend(oldState: RatchetState): RatchetSendResult
    {
        var result: RatchetSendResult? = null

        // The sender generates fresh new keys to add entropy
        val newLocalEphemeralKeypair = generateEphemeralKeypair()

        val copyOfOldState = RatchetState(oldState)
        var copyOfRemoteKeyBytes: ByteArray? = null
        var copyOfNewEphemeralPublicKeyWeAreSending: ByteArray? = null
        var copyOfNewEphemeralPrivateKey: ByteArray? = null

        return try {
            newLocalEphemeralKeypair.consume { public, private ->
                copyOfNewEphemeralPublicKeyWeAreSending = public.copyBytes()
                copyOfNewEphemeralPrivateKey = private.copyBytes()
            }
            require(copyOfNewEphemeralPublicKeyWeAreSending != null) { "Copy of outgoing remote public key is null"}

            copyOfOldState.use {
                copyOfRemoteKeyBytes = it.remoteEphemeralPublicKey.copyBytes()
                require(copyOfRemoteKeyBytes != null) { throw RedoHandshakeException("No remote public key to work with")}

                val newState = DHRatchet.perform(
                    oldState = copyOfOldState,
                    localEphemeralKeypair = EphemeralKeypair.from(copyOfNewEphemeralPublicKeyWeAreSending, copyOfNewEphemeralPrivateKey!!),
                    remotePublicKey = EphemeralPublicKey(copyOfRemoteKeyBytes)
                )
                result = RatchetSendResult(
                    newState,
                    EphemeralPublicKey(copyOfNewEphemeralPublicKeyWeAreSending),
                )
            }
        result ?: throw RedoHandshakeException("Trouble creating ratchet result")
        }
        catch(e: Exception) {
            throw RedoHandshakeException(e.message ?: "Something went wrong")
        }
        finally {
            copyOfOldState.close()
            newLocalEphemeralKeypair.close()
            copyOfNewEphemeralPublicKeyWeAreSending?.fill(0)
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

    fun ratchetForReceive(oldState: RatchetState, incomingEphemeralPublicKey: EphemeralPublicKey, incomingCounter: Int? = null): RatchetState {
        var copyOfOldState: RatchetState? = null
        var copyOfLocalEphemeralKeypair: EphemeralKeypair? = null
        var copyOfIncomingEphemeralPublicKey: EphemeralPublicKey? = null

        return try {
            copyOfOldState = RatchetState(oldState)
            copyOfLocalEphemeralKeypair = oldState.localEphemeralKeypair.copyOf()
            copyOfIncomingEphemeralPublicKey = EphemeralPublicKey(incomingEphemeralPublicKey.copyBytes())

            incomingCounter?.also {
                validateCounter(incomingCounter, oldState.counterLastReceivedKeyNum)
            }

            // TODO: The DHRatchet receives either an outgoing or incoming counter, +1 from the last one

            val resultingRatchetState = DHRatchet.perform(
                oldState = copyOfOldState,
                localEphemeralKeypair = copyOfLocalEphemeralKeypair,
                remotePublicKey = copyOfIncomingEphemeralPublicKey,
                counter = incomingCounter
            )
            resultingRatchetState
        } catch(e: Exception) {
            throw RedoHandshakeException(e.message ?: "Something went wrong while receiving a message")
        }
        finally {
            copyOfOldState?.close()
            copyOfLocalEphemeralKeypair?.close()
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

    fun symmetricRatchetFrom(oldState: RatchetState): RatchetState {
        return SymmetricRatchet.perform(oldState)
    }

    fun dhRatchet(
        oldState: RatchetState,
        localEphemeralKeypair: EphemeralKeypair,          // TODO: Safe to make this non-nullable?
        incomingPublicKey: EphemeralPublicKey           // Incoming ephemeral PK
    ): RatchetState {

        return DHRatchet.perform(
            oldState,
            localEphemeralKeypair,
            incomingPublicKey
        )
    }


    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): EphemeralKeypair {
        return EphemeralKeypair(MADH.generateKeypair())
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

}
