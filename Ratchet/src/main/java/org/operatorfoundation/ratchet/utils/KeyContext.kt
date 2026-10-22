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

    object Init {
        const val INFOPREFIX = "SHOUT-INIT"
    }

    object RootKey {
        const val SALT = "SHOUT-v1-Salt-RootKey"
        const val INFOPREFIX = "SHOUT-ROOT"
    }

    object ChainKey {
        const val INFOPREFIX = "SHOUT-CHAIN"
    }

}