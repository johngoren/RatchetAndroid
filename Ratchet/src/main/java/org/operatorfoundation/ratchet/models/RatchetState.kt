package org.operatorfoundation.ratchet.models

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeypair

// TODO: Does this need Autocloseable if it's passed around in a secure autocloseable container class?

/**
 * Represents the complete state of the double ratchet algorithm at a given point.
 *
 * @property rootKey The current root key
 * @property chainKey The current chain key
 * @property sharedKey The current shared key derived from ECDH
 * @property messageKey The current message key for encryption/decryption
 * @property localEphemeralKeypair The local ephemeral key pair
 * @property remoteEphemeralPublicKey The remote party's ephemeral public key
 */
class RatchetState(
    val localLongtermKeypair: SecureKeypair,
    val remoteLongtermPublicKey: Curve25519PublicKey,
    val rootKey: RootKey,
    val messageNumber: Int = 0,
    val chainKey: ChainKey? = null,
    val sharedKey: SharedKey? = null,
    val messageKey: MessageKey? = null,
    val localEphemeralKeypair: SecureKeypair? = null,
    val remoteEphemeralPublicKey: Curve25519PublicKey? = null,
    val sessionId: ByteArray = ByteArray(16),
    val monotonicCounter: Int = 0
) {

    fun deepCopy(
        localLongtermKeypair: SecureKeypair = this.localLongtermKeypair,
        remoteLongtermPublicKey: Curve25519PublicKey = this.remoteLongtermPublicKey,
        rootKey: RootKey = this.rootKey,
        messageNumber: Int = this.messageNumber,
        chainKey: ChainKey? = this.chainKey,
        sharedKey: SharedKey? = this.sharedKey,
        messageKey: MessageKey? = this.messageKey,
        localEphemeralKeypair: SecureKeypair? = this.localEphemeralKeypair,
        remoteEphemeralPublicKey: Curve25519PublicKey? = this.remoteEphemeralPublicKey): RatchetState
    {
        var copyOfLocalLongtermKeypair: SecureKeypair? = null

        localLongtermKeypair.use { localLongtermKeypair ->
            val tempCopyOfLocalLongtermKeypair = SecureKeypair(
                Curve25519KeyPair(
                    Curve25519PublicKey(localLongtermKeypair.publicKey.bytes.copyOf()),
                    Curve25519PrivateKey(localLongtermKeypair.privateKey.bytes.copyOf())
                )
            )
            copyOfLocalLongtermKeypair = tempCopyOfLocalLongtermKeypair
        }

        val copyOfRemoteLongtermPublicKey = Curve25519PublicKey(remoteLongtermPublicKey.bytes.copyOf())
        val copyOfRootKey = RootKey(rootKey.bytes.copyOf())
        val copyOfChainKey = if (chainKey != null) { ChainKey(chainKey.bytes.copyOf()) } else { null }
        val copyOfSharedKey = if (sharedKey != null) { SharedKey(sharedKey.bytes.copyOf()) } else { null }
        val copyOfMessageKey = if (messageKey != null) { MessageKey(messageKey.bytes.copyOf()) } else { null }

        var copyOfLocalEphemeralKeypair: SecureKeypair? = null

        localEphemeralKeypair?.use { localKeypair ->
            val tempCopyOfLocalEphemeralKeypair = Curve25519KeyPair(
                Curve25519PublicKey(localKeypair.publicKey.bytes.copyOf()),
                Curve25519PrivateKey(localKeypair.privateKey.bytes.copyOf())
            )
            copyOfLocalEphemeralKeypair = SecureKeypair(tempCopyOfLocalEphemeralKeypair)
        }

        val copyOfRemoteEphemeralPublicKey = if (remoteEphemeralPublicKey == null) { null } else {
            Curve25519PublicKey(remoteEphemeralPublicKey.bytes.copyOf())
        }

        require(copyOfLocalLongtermKeypair != null && copyOfLocalEphemeralKeypair != null) { "Could not copy keypairs "}

        return RatchetState(copyOfLocalLongtermKeypair, copyOfRemoteLongtermPublicKey, copyOfRootKey, messageNumber, copyOfChainKey, copyOfSharedKey, copyOfMessageKey, copyOfLocalEphemeralKeypair, copyOfRemoteEphemeralPublicKey, sessionId)
    }

    fun close() {
        localLongtermKeypair.use { localLongtermKeypair ->
            localLongtermKeypair.apply {
                publicKey.bytes.fill(0)
                privateKey.bytes.fill(0)
            }
        }
        rootKey.close()
        chainKey?.close()
        sharedKey?.close()
        messageKey?.close()
        localEphemeralKeypair?.use { localEphemeralKeypair ->
            localEphemeralKeypair.apply {
                publicKey.bytes.fill(0)
                privateKey.bytes.fill(0)
            }

        }
        remoteEphemeralPublicKey?.bytes?.fill(0)
    }
}