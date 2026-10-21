package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.Ratchet.NUM_BYTES_IN_SESSION_NONCE
import org.operatorfoundation.ratchet.Ratchet.RADIX_FOR_COUNTER_ENCODING
import org.operatorfoundation.ratchet.ratchets.MonotonicCounter
import java.nio.ByteBuffer

object ContextField {

    fun getInfoForInit(prefix: String, sessionNonce: ByteArray): ByteArray {
        require(sessionNonce.size == NUM_BYTES_IN_SESSION_NONCE) { "Session nonce was wrong size "}

        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)

        return ByteBuffer.allocate((prefixBytes.size + sessionNonce.size))
            .put(prefixBytes)
            .put(sessionNonce)
            .array()
    }


    fun getInfoBasic(prefix: String): ByteArray {
        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)

        return ByteBuffer.allocate((prefixBytes.size))
            .put(prefixBytes)
            .array()
    }

    fun getInfoWithCounter(prefix: String, counter: MonotonicCounter): ByteArray {
        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        val counterBytes = numberToHexBytes(counter)
        val bufferSize = prefixBytes.size + counterBytes.size

        return ByteBuffer.allocate(bufferSize)
            .put(prefixBytes)
            .put(counterBytes)
            .array()
    }

    // Utils

    private fun numberToHexBytes(number: Int): ByteArray {
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