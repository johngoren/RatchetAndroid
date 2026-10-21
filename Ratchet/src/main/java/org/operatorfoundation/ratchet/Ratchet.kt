package org.operatorfoundation.ratchet

import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc7748.X25519
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.Constants.MAX_COUNTER_NUM
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair
import org.operatorfoundation.ratchet.ratchets.DHRatchet
import org.operatorfoundation.ratchet.ratchets.MonotonicCounter
import org.operatorfoundation.ratchet.ratchets.SymmetricRatchet
import org.operatorfoundation.ratchet.utils.KeyContext
import org.operatorfoundation.ratchet.utils.ECDH
import org.operatorfoundation.ratchet.utils.HKDF

/**
 * Main API for the Double Ratchet algorithm.
 *
 * The Double Ratchet provides forward secrecy and break-in recovery for
 * asynchronous messaging by combining a Diffie-Hellman ratchet with a
 * symmetric key ratchet.
 *
 */

class RedoHandshakeException(message: String = "Something went wrong. You need to renegotiate the handshake"): Exception(message)

object Ratchet
{

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
    ): RatchetState
    {
        var copyOfRemotePublicKey: EphemeralPublicKey? = null

        copyOfRemotePublicKey = EphemeralPublicKey(initialRemotePublicKey.copyBytes())

        val copyOfInitialLocalKeypair = initialLocalKeypair.copyOf()
        var copyOfInitialLocalPrivateKey: PrivateKey? = null

        var hkdfOutput: ByteArray? = null
        var initialSharedSecret: Secret? = null
        var newState: RatchetState? = null

        return try {
            copyOfInitialLocalKeypair.consume { _, localPrivateKey ->

                localPrivateKey.consume {
                    copyOfInitialLocalPrivateKey = PrivateKey(it)
                }
                require(copyOfInitialLocalPrivateKey != null)

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                initialSharedSecret = ECDH.perform(copyOfInitialLocalPrivateKey, copyOfRemotePublicKey)

                hkdfOutput = HKDF.forRootKeyMaterial(
                    initialSharedSecret,
                    KeyContext.getInfoWithCounter(KeyContext.RootKey.INFOPREFIX, 0)
                )

                // Return initial state with defaults for optional fields
                newState = RatchetState(
                    rootKey = RootKey.fromHKDF(hkdfOutput.copyOf()),
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

                val dhCounter = it.counterOut + 1
                if (dhCounter > MAX_COUNTER_NUM) {
                    throw RedoHandshakeException("Maximum number of Shout messages exceeded. User needs to redo handshake.")
                }

                val ratchetedState = DHRatchet.perform(
                    oldState = copyOfOldState,
                    counter = dhCounter,
                    localEphemeralKeypair = EphemeralKeypair.from(copyOfNewEphemeralPublicKeyWeAreSending, copyOfNewEphemeralPrivateKey!!),
                    remotePublicKey = EphemeralPublicKey(copyOfRemoteKeyBytes)
                )

                var newState: RatchetState? = null

                ratchetedState.use { state ->
                    newState = RatchetState(state, counterOut = dhCounter)
                }

                result = RatchetSendResult(
                    newState!!,
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

    fun ratchetForReceive(oldState: RatchetState, incomingEphemeralPublicKey: EphemeralPublicKey, incomingCounter: Int = 1): RatchetState {
        var copyOfOldState: RatchetState? = null
        var copyOfLocalEphemeralKeypair: EphemeralKeypair? = null
        var copyOfIncomingEphemeralPublicKey: EphemeralPublicKey? = null

        return try {
            copyOfOldState = RatchetState(oldState)
            copyOfLocalEphemeralKeypair = oldState.localEphemeralKeypair.copyOf()
            copyOfIncomingEphemeralPublicKey = EphemeralPublicKey(incomingEphemeralPublicKey.copyBytes())

            copyOfOldState.use {
                validateCounter(incomingCounter, it.counterIn)
                checkForSkippedKeys(incomingCounter, it.counterIn)

                val resultingRatchetState = DHRatchet.perform(
                    oldState = copyOfOldState,
                    localEphemeralKeypair = copyOfLocalEphemeralKeypair,
                    remotePublicKey = copyOfIncomingEphemeralPublicKey,
                    counter = incomingCounter
                )
                var newState: RatchetState? = null

                resultingRatchetState.use { state ->
                    newState = RatchetState(state, counterIn = incomingCounter)
                }

                newState!!
            }
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
            throw SecurityException("ECDHE counter failed validation")
        }
    }

    private fun checkForSkippedKeys(incomingCounter: Int, lastReceivedCounterNum: Int) {
        if (incomingCounter > lastReceivedCounterNum + 1) {
            handleSkippedKeys()
        }
    }

    private fun handleSkippedKeys() {
        /**
         *  TODO in Shout Messages road map: Implement this feature that was originally
         *  deemed out of scope during development.
         *
         */
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
        localEphemeralKeypair: EphemeralKeypair,
        incomingPublicKey: EphemeralPublicKey,
        counter: MonotonicCounter = 1
    ): RatchetState {

        return DHRatchet.perform(
            oldState,
            localEphemeralKeypair,
            incomingPublicKey,
            counter
        )
    }


    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): EphemeralKeypair {
        return EphemeralKeypair(MADH.generateKeypair())
    }

}
