package org.operatorfoundation.ratchet.ratchets

import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.DoubleRatchet.NUM_BYTES_IN_KEY
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeyPair
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
        localEphemeralKeypair: SecureKeyPair,          // TODO: Safe to make this non-nullable?
        incomingPublicKey: Curve25519PublicKey,        // Incoming ephemeral PK
        incomingCounter: Int? = null
    ): SecureRatchetState
    {
        var copyOfLocalLongtermKeypair: SecureKeyPair? = null
        var copyOfLocalEphemeralPrivateKey: ByteArray? = null
        var copyOfIncomingPublicKey: Curve25519PublicKey? = null
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
                    copyOfLocalLongtermKeypair = localLongtermKeypair.copyOf()
                    copyOfIncomingPublicKey = Curve25519PublicKey(incomingPublicKey.bytes.copyOf())
                    copyOfOldRootKey = RootKey(rootKey.bytes)
                    copyOfSessionId = sessionId
                    messageNum = messageNumber
                }
            }

            // ** temporary workaround. Later we can ensure non-null **
            if (copyOfLocalEphemeralPrivateKey == null) {
                val newKeypair = MADH.generateKeypair()
                copyOfLocalEphemeralPrivateKey = newKeypair.privateKey.bytes

//                copyOfLocalLongtermKeypair!!.use { peek ->
//                    copyOfLocalEphemeralPrivateKey = peek.privateKey.bytes.copyOf()
//                }
            }
            // ** end temporary crutch **

            require(copyOfLocalLongtermKeypair != null) { "No copy available of local longterm keypair" }
            require(copyOfLocalEphemeralPrivateKey != null) { "No copy available of local ECDHE private key" }
            require(copyOfIncomingPublicKey != null) { "No copy of remote public key" }
            require(copyOfSessionId != null) { "No copy of session ID" }
            require(copyOfOldRootKey != null) { "No copy of old root key " }
            require(messageNum != null) { "No copy of message number " }

            // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
            sharedSecret = ECDH.perform(PrivateKey(copyOfLocalEphemeralPrivateKey!!.copyOf()), copyOfIncomingPublicKey)
            val newSharedKey = SharedKey.fromECDH(sharedSecret)

            // Derive new root and chain keys:
            // was: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
            // now: (R_n, C_n) = HKDF(R_{n-1}, S_n, {info context binding the key to session and counter nonces})

            // TODO: Make it the counter, not the message number?
            val contextBoundToSessionAndCounterNonces = ContextField.getInfoWithCounter(ContextField.ChainKey.INFOPREFIX, copyOfSessionId, incomingCounter ?: 0) // TODO: Remove fallback

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
                localLongtermKeypair = copyOfLocalLongtermKeypair,
                remoteLongtermPublicKey = copyOfIncomingPublicKey,
                rootKey = newRootKey,
                messageNumber = newMessageNumber,
                chainKey = newChainKey,
                sharedKey = newSharedKey,
                messageKey = messageKey,
                localEphemeralKeypair = localEphemeralKeypair,  // TODO: Check this!! And which one ends up in result!!
                remoteEphemeralPublicKey = incomingPublicKey,
                counterLastReceivedKeyNum = incomingCounter ?: null     // TODO: Remove fallback?
            )
            SecureRatchetState(newState)
        }
        catch(e: Exception) {
            throw e
        } finally {
            copyOfOldRootKey?.bytes?.fill(0)
            copyOfIncomingPublicKey?.bytes?.fill(0)
            copyOfLocalEphemeralPrivateKey?.fill(0)
            sharedSecret?.bytes?.fill(0)
            hkdfOutput?.fill(0)
            hmacOutput?.fill(0)
            oldState.close()
        }
    }

}