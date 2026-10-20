package org.operatorfoundation.ratchet.ratchets

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.Ratchet.NUM_BYTES_IN_KEY
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair
import org.operatorfoundation.ratchet.utils.ContextField
import org.operatorfoundation.ratchet.utils.ECDH
import org.operatorfoundation.ratchet.utils.HKDF
import org.operatorfoundation.ratchet.utils.HMAC


/**
 * Advances the ratchet _with_ new ephemeral keys (DH ratchet step).
 * This should be called when receiving a message with a new public key.
 *
 * @param oldState The current ratchet state
 * @param localEphemeralKeypair ECDHE keys
 * @param incomingPublicKey New remote ephemeral public key
 * @return The updated ratchet state
 */

object DHRatchet {

    // TODO: Defensive quality checks around any incoming key.

    fun perform(
        oldState: RatchetState,
        localEphemeralKeypair: EphemeralKeypair,
        remotePublicKey: EphemeralPublicKey,
        counter: Int? = null
    ): RatchetState
    {
        val copyOfOldState = RatchetState(oldState)
        require(oldState.isUsable) { "Tried to ratchet from an old state that has expired" }

        var newChainKey: ChainKey? = null
        var newRootKey: RootKey? = null
        var newSharedKey: SharedKey? = null
        var newMessageKey: MessageKey? = null

        var copyOfLocalEphemeralPublicKey: ByteArray? = null
        var copyOfLocalEphemeralPrivateKey: ByteArray? = null
        var copyOfRemotePublicKey: ByteArray? = remotePublicKey.copyBytes()
        var copyOfOldRootKey: ByteArray? = null
        var copyOfSessionId: ByteArray? = null

        var counterLastSent: Int? = null
        var counterLastReceived: Int? = null

        var messageNum: Int? = null
        var sharedSecret: Secret? = null
        var hkdfOutput: ByteArray? = null
        var hmacOutput: ByteArray? = null
        var copyOfNewChainKeyBytes: ByteArray? = null

        return try {
            localEphemeralKeypair.consume { localPublicKey, localPrivateKey ->
                copyOfLocalEphemeralPublicKey = localPublicKey.copyBytes()
                copyOfLocalEphemeralPrivateKey = localPrivateKey.copyBytes()
            }
            require(copyOfLocalEphemeralPrivateKey?.size == NUM_BYTES_IN_KEY) { "ECDHE key is wrong size "}

            copyOfRemotePublicKey = remotePublicKey.copyBytes()
            copyOfOldState.use {
                it.apply {
                    copyOfOldRootKey = rootKey.copyBytes()
                    copyOfSessionId = sessionId
                    messageNum = messageNumber
                }
            }

            require(copyOfSessionId != null) { "No copy of session ID" }
            require(copyOfOldRootKey != null) { "No copy of old root key " }
            require(messageNum != null) { "No copy of message number " }

            // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
            sharedSecret = ECDH.perform(PrivateKey(copyOfLocalEphemeralPrivateKey.copyOf()), EphemeralPublicKey(copyOfRemotePublicKey))
            newSharedKey = SharedKey.fromECDH(sharedSecret)

            // Derive new root and chain keys:
            // now: (R_n, C_n) = HKDF(R_{n-1}, S_n, {info context binding the key to session and counter nonces})

            val contextBoundToSessionAndCounterNonces = ContextField.getInfoWithCounter(ContextField.ChainKey.INFOPREFIX, copyOfSessionId, counter ?: 0) // TODO: Remove fallback

            hkdfOutput = HKDF.forRootAndChainMaterial(
                copyOfOldRootKey,
                sharedSecret,
                contextBoundToSessionAndCounterNonces
            )
            newRootKey = RootKey.fromHKDF(hkdfOutput)       // First 32 bytes
            newChainKey = ChainKey.fromHKDF(hkdfOutput)     // Second 32 bytes

            copyOfNewChainKeyBytes = newChainKey.copyBytes()
            require(copyOfNewChainKeyBytes != null) { "New chain key bytes were null"}

            // Increment message number and derive message key: M_n = HMAC(C_n, n)
            val newMessageNumber = messageNum + 1
            hmacOutput =
                HMAC.perform(copyOfNewChainKeyBytes, newMessageNumber.toString().toByteArray())
            newMessageKey = MessageKey.fromHMAC(hmacOutput)

            val newState = RatchetState(
                rootKey = newRootKey,
                messageNumber = newMessageNumber,
                chainKey = newChainKey,
                sharedKey = newSharedKey,
                messageKey = newMessageKey,
                localEphemeralKeypair = EphemeralKeypair(
                    Curve25519KeyPair (
                        Curve25519PublicKey(copyOfLocalEphemeralPublicKey!!),
                        Curve25519PrivateKey(copyOfLocalEphemeralPrivateKey!!)
                    )
                ),
                remoteEphemeralPublicKey = EphemeralPublicKey(copyOfRemotePublicKey),
                counterIn = counterLastReceived ?: 0,
                counterOut = counterLastSent ?: 0
            )
            newState
        }
        catch(e: Exception) {
            throw e
        } finally {
            newChainKey?.close()
            newRootKey?.close()
            newSharedKey?.close()
            newMessageKey?.close()

            copyOfOldRootKey?.fill(0)
            copyOfRemotePublicKey?.fill(0)
            copyOfLocalEphemeralPrivateKey?.fill(0)
            copyOfNewChainKeyBytes?.fill(0)
            sharedSecret?.close()
            hkdfOutput?.fill(0)
            hmacOutput?.fill(0)
            copyOfOldState.close()
        }
    }

}