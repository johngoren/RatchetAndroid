package org.operatorfoundation.ratchet

object Config {
    const val NUM_BYTES_IN_KEY = 32
    const val NUM_BYTES_IN_MESSAGE_COUNTER = 3
    const val NUM_BYTES_IN_SESSION_ID = 16
    const val NUM_BYTES_IN_SECRET = 32
    const val MAX_COUNTER_NUM = 65535
    const val RADIX_FOR_COUNTER_ENCODING = 16
    const val MAX_SKIP = 10
}