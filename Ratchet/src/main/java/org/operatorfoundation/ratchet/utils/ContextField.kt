package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.DoubleRatchet.NUM_BYTES_IN_SESSION_NONCE
import org.operatorfoundation.ratchet.DoubleRatchet.RADIX_FOR_COUNTER_ENCODING
import java.nio.ByteBuffer

object ContextField {

    fun getInfo(prefix: String, sessionNonce: ByteArray): ByteArray {
        require(sessionNonce.size == NUM_BYTES_IN_SESSION_NONCE) { "Session nonce was wrong size "}

        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)

        return ByteBuffer.allocate((prefixBytes.size + sessionNonce.size))
            .put(prefixBytes)
            .put(sessionNonce)
            .array()
    }

    fun getInfoWithCounter(prefix: String, sessionNonce: ByteArray, counter: Int): ByteArray {
        require(sessionNonce.size == NUM_BYTES_IN_SESSION_NONCE) { "Session nonce was wrong size"}

        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        val counterBytes = numberToHexBytes(counter)
        val bufferSize = prefixBytes.size + sessionNonce.size + counterBytes.size

        return ByteBuffer.allocate(bufferSize)
            .put(prefixBytes)
            .put(sessionNonce)
            .put(counterBytes)
            .array()
    }

    // Utils

    private fun numberToHexBytes(number: Int): ByteArray {
        return number
            .toString(RADIX_FOR_COUNTER_ENCODING)
            .toByteArray(Charsets.UTF_8)
    }
}