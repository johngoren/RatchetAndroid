package org.operatorfoundation.ratchet.models

import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.keys.secure.EphemeralKeypair

// TODO: Getters that check whether we are correctly consuming
// TODO: Check that keys we are using are alive

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
    val rootKey: RootKey,
    val messageNumber: Int = 0,
    val chainKey: ChainKey? = null,
    val sharedKey: SharedKey? = null,
    val messageKey: MessageKey? = null,
    val localEphemeralKeypair: EphemeralKeypair,
    val remoteEphemeralPublicKey: EphemeralPublicKey,
    val sessionId: ByteArray = ByteArray(16),
    var counterLastReceivedKeyNum: Int = 0,
    var counterLastSentKeyNum: Int = 0
): AutoCloseable {

    private var isDestroyed: Boolean = false

    val isUsable: Boolean
        get() {
            return !isDestroyed
        }

    constructor(oldState: RatchetState,
                rootKey: RootKey = oldState.rootKey,
                messageNumber: Int = oldState.messageNumber,
                chainKey: ChainKey? = oldState.chainKey,
                sharedKey: SharedKey? = oldState.sharedKey,
                messageKey: MessageKey? = oldState.messageKey,
                localEphemeralKeypair: EphemeralKeypair = oldState.localEphemeralKeypair,
                remoteEphemeralPublicKey: EphemeralPublicKey = oldState.remoteEphemeralPublicKey,
                sessionId: ByteArray = oldState.sessionId,
                counterLastReceivedKeyNum: Int = oldState.counterLastReceivedKeyNum,
                counterLastSentKeyNum: Int = oldState.counterLastSentKeyNum
    ) : this(
            rootKey = RootKey(rootKey.copyBytes()),
            messageNumber = messageNumber,
            chainKey = if (chainKey != null) { ChainKey(chainKey.copyBytes()) } else null,
            sharedKey = if (sharedKey != null) { SharedKey(sharedKey.copyBytes()) } else null,
            messageKey = if (messageKey != null) { MessageKey(messageKey.copyBytes())} else null,
            localEphemeralKeypair = localEphemeralKeypair.copyOf(),
            remoteEphemeralPublicKey = EphemeralPublicKey(remoteEphemeralPublicKey.copyBytes()),
            sessionId = sessionId,
            counterLastReceivedKeyNum = counterLastReceivedKeyNum,
            counterLastSentKeyNum = counterLastSentKeyNum
        ) {
        require(oldState.isUsable) { "Tried to copy a state that has expired."}
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