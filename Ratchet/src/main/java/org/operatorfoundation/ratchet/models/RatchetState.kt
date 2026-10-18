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
 * @property remotePublicEphemeralKey The remote party's ephemeral public key
 */
class RatchetState(
    val rootKey: RootKey,
    val messageNumber: Int = 0,
    val chainKey: ChainKey? = null,
    val sharedKey: SharedKey? = null,
    val messageKey: MessageKey? = null,
    val localEphemeralKeypair: EphemeralKeypair? = null,
    val remotePublicEphemeralKey: EphemeralPublicKey? = null,
    val sessionId: ByteArray = ByteArray(16),
    var counterLastReceivedKeyNum: Int = 0,
    var counterLastSentKeyNum: Int = 0
): AutoCloseable {

    // TODO: Make copies.

    constructor(previous: RatchetState,
                rootKey: RootKey = previous.rootKey,
                messageNumber: Int = previous.messageNumber,
                chainKey: ChainKey? = previous.chainKey,
                sharedKey: SharedKey? = previous.sharedKey,
                messageKey: MessageKey? = previous.messageKey,
                localEphemeralKeypair: EphemeralKeypair? = previous.localEphemeralKeypair,
                remoteEphemeralPublicKey: EphemeralPublicKey? = previous.remotePublicEphemeralKey,
                sessionId: ByteArray = previous.sessionId,
                counterLastReceivedKeyNum: Int = previous.counterLastReceivedKeyNum,
                counterLastSentKeyNum: Int = previous.counterLastSentKeyNum
    ) : this(
            rootKey = rootKey,
            messageNumber = messageNumber,
            chainKey = chainKey,
            sharedKey = sharedKey,
            messageKey = messageKey,
            localEphemeralKeypair = localEphemeralKeypair,
            remotePublicEphemeralKey = remoteEphemeralPublicKey,
            sessionId = sessionId,
            counterLastReceivedKeyNum = counterLastReceivedKeyNum,
            counterLastSentKeyNum = counterLastSentKeyNum
        )

    override fun close() {
        rootKey.close()
        chainKey?.close()
        sharedKey?.close()
        messageKey?.close()
        localEphemeralKeypair?.close()
//        lastKnownRemotePublicEphemeralKey?.bytes?.fill(0)
    }
}