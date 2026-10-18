package org.operatorfoundation.ratchet.models.keys.secure

import androidx.annotation.VisibleForTesting
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.PrivateKey

open class EphemeralKeypair(curve25519KeyPair: Curve25519KeyPair): AutoCloseable {
    var isDestroyed: Boolean = false

    private val _publicKeyBytes: ByteArray = curve25519KeyPair.publicKey.bytes.copyOf()

    private val _privateKeyBytes: ByteArray = curve25519KeyPair.privateKey.bytes.copyOf()

    private val _keypair: Curve25519KeyPair
        get() {
            return Curve25519KeyPair(Curve25519PublicKey(_publicKeyBytes), Curve25519PrivateKey(_privateKeyBytes))
        }


    fun consume(block: (EphemeralPublicKey, PrivateKey)->Unit) {
        check(!isDestroyed) { "Keypair has been destroyed "}
        if (!isDestroyed) {
            block(EphemeralPublicKey(_publicKeyBytes), PrivateKey(_privateKeyBytes))
        }
    }

    private fun copyPublicKeyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return _keypair.publicKey.bytes.copyOf()
    }

    private fun copyPrivateKeyBytes(): ByteArray {
        check(!isDestroyed) { "Key has been destroyed "}
        return _keypair.privateKey.bytes.copyOf()
    }

    fun copyOf(): EphemeralKeypair {
        val publicBytes = copyPublicKeyBytes()
        val privateBytes = copyPrivateKeyBytes()

        return EphemeralKeypair(
            Curve25519KeyPair(Curve25519PublicKey(publicBytes), Curve25519PrivateKey(privateBytes))
        )
    }

    override fun close() {
        if (!isDestroyed) {
            _publicKeyBytes.fill(0)
            _privateKeyBytes.fill(0)
            isDestroyed = true
        }
    }

    override fun toString(): String {
        return "Keypair" + if (isDestroyed) " ***destroyed*** " else " redacted for security"
    }

    override fun equals(other: Any?): Boolean
    {
        throw SecurityException("Equality operations have been disabled for security")
    }

    override fun hashCode(): Int
    {
        throw SecurityException("Hash codes have been disabled for security")
    }

    @VisibleForTesting
    val publicKeyBytesForTesting: ByteArray
        get() {
            return _publicKeyBytes
        }

    val privateKeyBytesForTesting: ByteArray
        get() {
            return _privateKeyBytes
        }

}