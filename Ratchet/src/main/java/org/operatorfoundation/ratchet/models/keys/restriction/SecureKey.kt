package org.operatorfoundation.ratchet.models.keys.restriction

import org.operatorfoundation.ratchet.Ratchet

open class SecureKey(private val keyBytes: ByteArray) {
    var isDestroyed: Boolean = false

    private val _keyBytes: ByteArray

    init {
        require(keyBytes.size == Ratchet.NUM_BYTES_IN_KEY) {
            "AES-256 key must be ${Ratchet.NUM_BYTES_IN_KEY} bytes"
        }
        _keyBytes = keyBytes.copyOf()
//        keyBytes.fill(0)
    }

    // TODO: Replace with use block exclusively
    val bytes: ByteArray
        get() {
            check(!isDestroyed) { "Key has been destroyed "}
            return _keyBytes.copyOf()
        }


    fun use(block: (ByteArray)->Unit) {
        check(!isDestroyed) { "Key has been destroyed "}
        if (!isDestroyed) {
            block(_keyBytes)
        }
    }

    fun copyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return _keyBytes.copyOf()
    }

    fun close() {
//        if (!isDestroyed) {
//            keyBytes.fill(0)
//            isDestroyed = true
//        }
    }

    override fun toString(): String {
        return "Symmetric key" +
                " redacted for security"
    }

    override fun equals(other: Any?): Boolean
    {
        throw SecurityException("Equality operations have been disabled for security")
    }

    override fun hashCode(): Int
    {
        throw SecurityException("Hash codes have been disabled for security")
    }

}