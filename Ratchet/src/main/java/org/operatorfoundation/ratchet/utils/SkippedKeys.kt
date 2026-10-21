package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.Constants
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.ratchets.SymmetricRatchet

/**
 * Skipped Keys
 *
 * Signal-style algorithm for catching up on skipped keys. This is
 * still in alpha and was originally ruled out of scope during
 * development.
 */

object SkippedKeys {

    fun handle(
        state: RatchetState,
        counter: Int
    ): RatchetState {
        val copyOfState = RatchetState(state)

        copyOfState.use {
            val skippedKeysMap = it.skippedKeys.toMutableMap() ?: mutableMapOf()
            val skipCount = counter - it.counterIn - 1
            require(skipCount <= Constants.MAX_SKIP) { "Too many messages skipped: ($skipCount > ${Constants.MAX_SKIP})" }

            var _state = RatchetState(it)
            val lastCounterReceived = it.counterIn

            for (counter in (lastCounterReceived) until counter) {
                val copyOfStateCache = SymmetricRatchet.perform(_state)
                _state.close()

                _state = RatchetState(
                    copyOfStateCache,
                )
                copyOfStateCache.close()

                _state.messageKey?.let { messageKey ->
                    skippedKeysMap[counter] = messageKey.copyBytes()
                }
            }
            return RatchetState(_state, skippedKeys=skippedKeysMap)
        }
    }

}