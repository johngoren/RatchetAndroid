package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.Ratchet.VALID_KEY_LENGTH


// TODO: Make bytes private and access only through use()
// TODO: Make a copy of what is passed in.
// TODO: The copyOf here returns a copy of a primitive, right? We can
// assume that's the way Assured prefers copies to be consistently made


open class RestrictedKey(private val keyBytes: ByteArray) {
    var isDestroyed: Boolean = false

    private val _keyBytes: ByteArray

    init {
        require(keyBytes.size == VALID_KEY_LENGTH) {
            "AES-256 key must be $VALID_KEY_LENGTH bytes"
        }
        _keyBytes = keyBytes
    }

    // TODO: Replace with use block exclusively
    val bytes: ByteArray
        get() {
            check(!isDestroyed) { "Key has been destroyed "}
            return keyBytes.copyOf()
        }


    fun use(block: (ByteArray)->Unit) {
        check(!isDestroyed) { "Key has been destroyed "}
        if (!isDestroyed) {
            block(keyBytes)
        }
    }

    fun copyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return keyBytes.copyOf()
    }

    fun close() {
//        if (!isDestroyed) {
//            keyBytes.fill(0)
//            isDestroyed = true
//        }
    }

//    override fun toString(): String {
//        return this.toString()
////        return "Symmetric key" +
////                " redacted for security"
//    }

//    override fun equals(other: Any?): Boolean
//    {
//        throw SecurityException("Equality operations have been disabled for security")
//    }
//
//    override fun hashCode(): Int
//    {
//        throw SecurityException("Hash codes have been disabled for security")
//    }


}