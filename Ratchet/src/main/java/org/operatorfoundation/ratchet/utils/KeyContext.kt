package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.Config.RADIX_FOR_COUNTER_ENCODING
import org.operatorfoundation.ratchet.ratchets.MonotonicCounter
import java.nio.ByteBuffer

object KeyContext {

    fun getInfoWithCounter(prefix: String, sessionId: ByteArray, counter: MonotonicCounter): ByteArray {
        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        val counterBytes = numberToHexBytes(counter)
        val bufferSize = prefixBytes.size + sessionId.size + counterBytes.size

        return ByteBuffer.allocate(bufferSize)
            .put(prefixBytes)
            .put(counterBytes)
            .array()
    }

    // Utils

    private fun numberToHexBytes(number: MonotonicCounter): ByteArray {
        return number
            .toString(RADIX_FOR_COUNTER_ENCODING)
            .toByteArray(Charsets.UTF_8)
    }

    object RootKey {
        const val SALT = "SHOUT-v1-Salt-RootKey"
        const val INFOPREFIX = "SHOUT-ROOT"
    }

    object RootAndChainKeys {
        const val SALT = "SHOUT-v1-Salt-RootAndChainKeys"
        const val INFOPREFIX = "SHOUT-ROOT-AND-CHAIN"
    }

    object SharedKey {
        const val SALT = "Shout-v1-Salt-SharedKey"
        const val INFOPREFIX = "SHOUT-SHARED-KEY"
    }

}