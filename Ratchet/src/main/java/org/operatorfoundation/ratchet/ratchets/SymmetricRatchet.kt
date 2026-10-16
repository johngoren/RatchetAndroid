package org.operatorfoundation.ratchet.ratchets

import org.operatorfoundation.ratchet.models.SecureRatchetState
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.HMAC

object SymmetricRatchet {

    /**
     * Advances the ratchet without new keys (symmetric ratchet step).
     * This should be called when sending/receiving multiple messages
     * without a key change (consecutive messages, same sender).
     *
     * @param oldState The current ratchet state
     * @return The updated ratchet state with new chain and message keys
     */

    fun perform(oldState: SecureRatchetState): SecureRatchetState
    {
        var nextRatchetState: SecureRatchetState? = null
        var copyOfOldChainKey: ByteArray? = null
        var chainHmacOutput: ByteArray? = null
        var messageHmacOutput: ByteArray? = null

        return try {
            oldState.use { oldStatePeek ->

                // Ensure we have a chain key to work with
                requireNotNull(oldStatePeek.chainKey) { "Cannot ratchet without a chain key. Call ratchetInternalWithNewEntropy first." }

                copyOfOldChainKey = oldStatePeek.chainKey.bytes.copyOf()

                // Increment message number
                val newMessageNumber = oldStatePeek.messageNumber + 1

                // Derive new chain key: C_n = HMAC(C_{n-1}, n)
                chainHmacOutput = HMAC.perform(
                    copyOfOldChainKey,
                    newMessageNumber.toString().toByteArray()
                )
                val newChainKey = ChainKey.fromHMAC(chainHmacOutput)

                // Derive new message key: M_n = HMAC(C_n, n)
                messageHmacOutput = HMAC.perform(
                    key=newChainKey.bytes,
                    data=newMessageNumber.toString().toByteArray()
                )

                val newState = oldStatePeek.copy(
                    messageNumber = newMessageNumber,
                    chainKey = newChainKey,
                    messageKey = MessageKey.fromHMAC(messageHmacOutput)
                )
                nextRatchetState = SecureRatchetState(newState)
            }

            nextRatchetState ?: throw Exception("Null ratchet state")
        }
        catch(e: Exception) {
            throw e // TODO: More specific error-handling
        }
        finally {
            chainHmacOutput?.fill(0)
            messageHmacOutput?.fill(0)
            copyOfOldChainKey?.fill(0)
            oldState.close()
        }
    }



}