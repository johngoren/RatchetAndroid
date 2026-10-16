package org.operatorfoundation.ratchet.ratchets

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.DoubleRatchet.NUM_BYTES_IN_KEY
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.secure.SecureKey
import org.operatorfoundation.ratchet.models.keys.secure.SecureKeyPair
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
    // TODO: Understand better how we store or do not store ECDHE in state.

    fun perform(
        oldState: SecureRatchetState,
        localEphemeralKeypair: SecureKeyPair,
        remotePublicKey: Curve25519PublicKey,        // Incoming ephemeral PK
        counter: Int? = null,
        outgoingCounter: Int? = null
    ): SecureRatchetState
    {
        var copyOfLocalEphemeralPrivateKey: ByteArray? = null
        var copyOfRemotePublicKey: Curve25519PublicKey? = null
        var copyOfOldRootKey: SecureKey? = null
        var copyOfSessionId: ByteArray? = null
        var messageNum: Int? = null
        var sharedSecret: Secret? = null
        var hkdfOutput: ByteArray? = null
        var hmacOutput: ByteArray? = null

        return try {
            localEphemeralKeypair.use { localECDHEPeek ->
                require(localECDHEPeek.privateKey.bytes.size == NUM_BYTES_IN_KEY) { "ECDHE key is wrong size "}
                copyOfLocalEphemeralPrivateKey = localECDHEPeek.privateKey.bytes.copyOf()
            }

            oldState.use { oldStatePeek ->
                oldStatePeek.apply {
                    copyOfRemotePublicKey = Curve25519PublicKey(remotePublicKey.bytes.copyOf())
                    copyOfOldRootKey = RootKey(rootKey.bytes)
                    copyOfSessionId = sessionId
                    messageNum = messageNumber
                }
            }

            require(copyOfLocalEphemeralPrivateKey != null) { "No copy available of local ECDHE private key" }
            require(copyOfRemotePublicKey != null) { "No copy of remote public key" }
            require(copyOfSessionId != null) { "No copy of session ID" }
            require(copyOfOldRootKey != null) { "No copy of old root key " }
            require(messageNum != null) { "No copy of message number " }

            // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
            sharedSecret = ECDH.perform(PrivateKey(copyOfLocalEphemeralPrivateKey.copyOf()), copyOfRemotePublicKey)
            val newSharedKey = SharedKey.fromECDH(sharedSecret)

            // Derive new root and chain keys:
            // was: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
            // now: (R_n, C_n) = HKDF(R_{n-1}, S_n, {info context binding the key to session and counter nonces})

            val contextBoundToSessionAndCounterNonces = ContextField.getInfoWithCounter(ContextField.ChainKey.INFOPREFIX, copyOfSessionId, counter ?: 0) // TODO: Remove fallback

            hkdfOutput = HKDF.forRootAndChainMaterial(
                copyOfOldRootKey.bytes,
                sharedSecret,
                contextBoundToSessionAndCounterNonces
            )
            val newRootKey = RootKey.fromHKDF(hkdfOutput)
            val newChainKey = ChainKey.fromHKDF(hkdfOutput)

            // Increment message number and derive message key: M_n = HMAC(C_n, n)
            val newMessageNumber = messageNum + 1
            hmacOutput =
                HMAC.perform(newChainKey.bytes, newMessageNumber.toString().toByteArray())
            val messageKey = MessageKey.fromHMAC(hmacOutput)

            val newState = RatchetState(
                rootKey = newRootKey,
                messageNumber = newMessageNumber,
                chainKey = newChainKey,
                sharedKey = newSharedKey,
                messageKey = messageKey,
                localEphemeralKeypair = localEphemeralKeypair.copyOf(),
                lastKnownRemotePublicEphemeralKey = Curve25519PublicKey(copyOfRemotePublicKey.bytes.copyOf()),

                counterLastReceivedKeyNum = counter ?: 0    // TODO: Remove fallback?
            )
            SecureRatchetState(newState)
        }
        catch(e: Exception) {
            throw e
        } finally {
//            copyOfOldRootKey?.bytes?.fill(0)
//            copyOfRemotePublicKey?.bytes?.fill(0)
//            copyOfLocalEphemeralPrivateKey?.fill(0)
//            sharedSecret?.bytes?.fill(0)
//            hkdfOutput?.fill(0)
//            hmacOutput?.fill(0)
//            oldState.close()
        }
    }

}