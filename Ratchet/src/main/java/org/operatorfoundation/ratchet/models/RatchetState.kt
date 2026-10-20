package org.operatorfoundation.ratchet.models

import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair

// TODO: Getters that check whether we are correctly consuming

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
    rootKey: RootKey,
    messageNumber: Int = 0,
    chainKey: ChainKey? = null,
    sharedKey: SharedKey? = null,
    messageKey: MessageKey? = null,
    localEphemeralKeypair: EphemeralKeypair,
    remoteEphemeralPublicKey: EphemeralPublicKey,
    sessionId: ByteArray = ByteArray(16),
    counterIn: Int = 0,
    counterOut: Int = 0
): AutoCloseable {

    val rootKey = RootKey(rootKey.copyBytes())
    val messageNumber = messageNumber
    val chainKey = if (chainKey != null) { ChainKey(chainKey.copyBytes()) } else null
    val sharedKey = if (sharedKey != null) { SharedKey(sharedKey.copyBytes()) } else null
    val messageKey = if (messageKey != null) { MessageKey(messageKey.copyBytes()) } else null
    val localEphemeralKeypair = localEphemeralKeypair.copyOf()
    val remoteEphemeralPublicKey = EphemeralPublicKey(remoteEphemeralPublicKey.copyBytes())
    val sessionId = sessionId.copyOf()
    val counterIn = counterIn
    val counterOut = counterOut

    private var isDestroyed: Boolean = false

    val isUsable: Boolean
        get() {
            return !isDestroyed
        }

    // Secondary constructor for copying and mutating an existing state
    constructor(originalState: RatchetState,
                rootKey: RootKey = originalState.rootKey,
                messageNumber: Int = originalState.messageNumber,
                chainKey: ChainKey? = originalState.chainKey,
                sharedKey: SharedKey? = originalState.sharedKey,
                messageKey: MessageKey? = originalState.messageKey,
                localEphemeralKeypair: EphemeralKeypair = originalState.localEphemeralKeypair,
                remoteEphemeralPublicKey: EphemeralPublicKey = originalState.remoteEphemeralPublicKey,
                sessionId: ByteArray = originalState.sessionId,
                counterIn: Int = originalState.counterIn,
                counterOut: Int = originalState.counterOut
    ) : this(
            rootKey = RootKey(rootKey.copyBytes()),
            messageNumber = messageNumber,
            chainKey = if (chainKey != null) { ChainKey(chainKey.copyBytes()) } else null,
            sharedKey = if (sharedKey != null) { SharedKey(sharedKey.copyBytes()) } else null,
            messageKey = if (messageKey != null) { MessageKey(messageKey.copyBytes())} else null,
            localEphemeralKeypair = localEphemeralKeypair.copyOf(),
            remoteEphemeralPublicKey = EphemeralPublicKey(remoteEphemeralPublicKey.copyBytes()),
            sessionId = sessionId,
            counterIn = counterIn,
            counterOut = counterOut
        ) {
        require(originalState.isUsable) { "Tried to copy a state that has expired."}
    }

    override fun toString(): String {
        return if (isDestroyed) " ***destroyed state** " else " usable state ready for ratcheting "
    }

    override fun close() {
        isDestroyed = true

        rootKey.close()
        chainKey?.close()
        sharedKey?.close()
        messageKey?.close()
        localEphemeralKeypair.close()
        remoteEphemeralPublicKey.close()
    }

}