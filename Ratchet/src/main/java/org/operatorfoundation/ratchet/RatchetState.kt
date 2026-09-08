package org.operatorfoundation.ratchet

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PublicKey

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
    val localLongtermKeypair: Curve25519KeyPair,
    val remoteLongtermPublicKey: Curve25519PublicKey,
    val rootKey: RootKey,
    val messageNumber: Int = 0,
    val chainKey: ChainKey? = null,
    val sharedKey: SharedKey? = null,
    val messageKey: MessageKey? = null,
    val localEphemeralKeypair: Curve25519KeyPair? = null,
    val remoteEphemeralPublicKey: Curve25519PublicKey? = null
) {

    fun copy(
        localLongtermKeypair: Curve25519KeyPair = this.localLongtermKeypair,
        remoteLongtermPublicKey: Curve25519PublicKey = this.remoteLongtermPublicKey,
        rootKey: RootKey = this.rootKey,
        messageNumber: Int = this.messageNumber,
        chainKey: ChainKey? = this.chainKey,
        sharedKey: SharedKey? = this.sharedKey,
        messageKey: MessageKey? = this.messageKey,
        localEphemeralKeypair: Curve25519KeyPair? = this.localEphemeralKeypair,
        remoteEphemeralPublicKey: Curve25519PublicKey? = this.remoteEphemeralPublicKey): RatchetState
    {
        return RatchetState(localLongtermKeypair, remoteLongtermPublicKey, rootKey, messageNumber, chainKey, sharedKey, messageKey, localEphemeralKeypair, remoteEphemeralPublicKey)
    }
}
