package org.operatorfoundation.ratchet.models

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.secure.SecureKeyPair

// TODO: Does this need Autocloseable if it's passed around in a secure autocloseable container class?

/**
 * Represents the complete state of the double ratchet algorithm at a given point.
 *
 * @property rootKey The current root key
 * @property chainKey The current chain key
 * @property sharedKey The current shared key derived from ECDH
 * @property messageKey The current message key for encryption/decryption
 * @property localEphemeralKeypair The local ephemeral key pair
 * @property lastKnownRemotePublicEphemeralKey The remote party's ephemeral public key
 */
class RatchetState(
    val rootKey: RootKey,
    val messageNumber: Int = 0,
    val chainKey: ChainKey? = null,
    val sharedKey: SharedKey? = null,
    val messageKey: MessageKey? = null,
    val localEphemeralKeypair: SecureKeyPair? = null,
    val lastKnownRemotePublicEphemeralKey: Curve25519PublicKey? = null,
    val sessionId: ByteArray = ByteArray(16),
    var counterLastReceivedKeyNum: Int = 0,
    var counterLastSentKeyNum: Int = 0
) {

    fun copy(
        rootKey: RootKey = this.rootKey,
        messageNumber: Int = this.messageNumber,
        chainKey: ChainKey? = this.chainKey,
        sharedKey: SharedKey? = this.sharedKey,
        messageKey: MessageKey? = this.messageKey,
        localEphemeralKeypair: SecureKeyPair? = this.localEphemeralKeypair,
        remoteEphemeralPublicKey: Curve25519PublicKey? = this.lastKnownRemotePublicEphemeralKey): RatchetState
    {
        val copyOfRootKey = RootKey(rootKey.bytes.copyOf())
        val copyOfChainKey = if (chainKey != null) { ChainKey(chainKey.bytes.copyOf()) } else { null }
        val copyOfSharedKey = if (sharedKey != null) { SharedKey(sharedKey.bytes.copyOf()) } else { null }
        val copyOfMessageKey = if (messageKey != null) { MessageKey(messageKey.bytes.copyOf()) } else { null }

        var copyOfLocalEphemeralKeypair: SecureKeyPair? = null

        localEphemeralKeypair?.use { localKeypair ->
            val tempCopyOfLocalEphemeralKeypair = Curve25519KeyPair(
                Curve25519PublicKey(localKeypair.publicKey.bytes.copyOf()),
                Curve25519PrivateKey(localKeypair.privateKey.bytes.copyOf())
            )
            copyOfLocalEphemeralKeypair = SecureKeyPair(tempCopyOfLocalEphemeralKeypair)
        }
        require(copyOfLocalEphemeralKeypair != null) { throw Exception("Missing local ephemeral keypair") }

        var copyOfRemoteEphemeralPublicKey: Curve25519PublicKey? = null
        remoteEphemeralPublicKey?.also {
            copyOfRemoteEphemeralPublicKey = Curve25519PublicKey(it.bytes)
        }
        return RatchetState( copyOfRootKey, messageNumber, copyOfChainKey, copyOfSharedKey, copyOfMessageKey, copyOfLocalEphemeralKeypair, copyOfRemoteEphemeralPublicKey, sessionId)
    }

    fun close() {
//        rootKey.close()
//        chainKey?.close()
//        sharedKey?.close()
//        messageKey?.close()
//        localEphemeralKeypair?.close()
//        lastKnownRemotePublicEphemeralKey?.bytes?.fill(0)
    }
}