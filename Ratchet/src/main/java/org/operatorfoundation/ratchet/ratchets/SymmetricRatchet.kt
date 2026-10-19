package org.operatorfoundation.ratchet.ratchets

import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.utils.HMAC

object SymmetricRatchet {

    /**
     * Advances the ratchet without new keys (symmetric ratchet step).
     * This should be called when sending/receiving multiple messages
     * without a key change (consecutive messages, same sender).
     *
     * @param previousState The current ratchet state
     * @return The updated ratchet state with new chain and message keys
     */

    fun perform(previousState: RatchetState): RatchetState
    {
        var newRatchetState: RatchetState? = null
        var copyOfOldChainKey: ByteArray? = null
        var copyOfNewChainKey: ByteArray? = null
        var chainHmacOutput: ByteArray? = null
        var messageHmacOutput: ByteArray? = null

        return try {
            previousState.use { oldState ->
                require(oldState.isUsable) { "Tried to ratchet from an old state that was expired." }

                // Ensure we have a chain key to work with
                requireNotNull(oldState.chainKey) { "Cannot ratchet without a chain key. Call ratchetInternalWithNewKey first." }
                require(oldState.chainKey.isUsable()) { "Tried to ratchet from a chain key that had been destroyed" }

                oldState.chainKey.consume {
                    copyOfOldChainKey = it
                }
                require(copyOfOldChainKey != null) { "Tried to use chain key bytes that were null" }

                // Increment message number
                val newMessageNumber = oldState.messageNumber + 1

                // Derive new chain key: C_n = HMAC(C_{n-1}, n)
                chainHmacOutput = HMAC.perform(
                    copyOfOldChainKey,
                    newMessageNumber.toString().toByteArray()
                )
                val newChainKey = ChainKey.fromHMAC(chainHmacOutput)
                newChainKey.consume {
                    copyOfNewChainKey = it
                }
                require(copyOfNewChainKey != null) { "Tried to use new chain key bytes, but they were null"}

                // Derive new message key: M_n = HMAC(C_n, n)
                messageHmacOutput = HMAC.perform(
                    key=copyOfNewChainKey,
                    data=newMessageNumber.toString().toByteArray()
                )

                val newState = RatchetState(
                    oldState = oldState,
                    messageNumber = newMessageNumber,
                    chainKey = ChainKey(newChainKey.copyBytes()),
                    messageKey = MessageKey.fromHMAC(messageHmacOutput.copyOf())
                )
                newRatchetState = newState
            }
            newRatchetState ?: throw Exception("Null ratchet state")
        }
        catch(e: Exception) {
            throw e // TODO: More specific error-handling
        }
        finally {
            chainHmacOutput?.fill(0)
            messageHmacOutput?.fill(0)
            copyOfOldChainKey?.fill(0)
            copyOfNewChainKey?.fill(0)
            previousState.close()
        }
    }

}