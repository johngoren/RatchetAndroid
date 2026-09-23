package org.operatorfoundation.ratchet.models.keys.restriction

import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey

open class RestrictedKeyPair(private val curve25519KeyPair: Curve25519KeyPair) {
    var isDestroyed: Boolean = false

    private val _publicKeyBytes: ByteArray = curve25519KeyPair.publicKey.bytes.copyOf()
    private val _privateKeyBytes: ByteArray = curve25519KeyPair.privateKey.bytes.copyOf()

    private val _keypair: Curve25519KeyPair
        get() {
            return Curve25519KeyPair(Curve25519PublicKey(_publicKeyBytes), Curve25519PrivateKey(_privateKeyBytes))
        }

    fun use(block: (Curve25519KeyPair)->Unit) {
        check(!isDestroyed) { "Keypair has been destroyed "}
        if (!isDestroyed) {
            block(_keypair)
        }
    }

    fun copyPublicKeyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return _keypair.publicKey.bytes.copyOf()
    }

    fun copyPrivateKeyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return _keypair.privateKey.bytes.copyOf()
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