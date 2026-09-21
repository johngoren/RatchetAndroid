package org.operatorfoundation.ratchet.keys

import java.security.Security

abstract class RestrictedKey(val bytes: ByteArray) {

    // TODO: Holds private value that can only be used once via "use"
    // TODO: Zeroizes when closed.

    override fun equals(other: Any?): Boolean
    {
        throw SecurityException("No equality operations allowed")
    }

    override fun hashCode(): Int
    {
        throw SecurityException("No hash codes allowed")
    }

}