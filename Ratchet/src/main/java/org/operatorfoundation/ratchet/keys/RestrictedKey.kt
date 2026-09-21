package org.operatorfoundation.ratchet.keys


// TODO: Make bytes private and access only through use()
// TODO: Make a copy of what is passed in.
// TODO: The copyOf here returns a copy of a primitive, right? We can
// assume that's the way Assured prefers copies to be consistently made

abstract class RestrictedKey(val bytes: ByteArray): AutoCloseable {

    var isDestroyed: Boolean = false

    fun use(block: (ByteArray)->Unit) {
        check(!isDestroyed) { "Key has been destroyed "}
        if (!isDestroyed) {
            block(bytes)
        }
    }

    fun copyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return bytes.copyOf()
    }

    override fun close() {
        if (!isDestroyed) {
            bytes.fill(0)
            isDestroyed = true
        }
    }

    override fun toString(): String {
        return "Key redacted for security"
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