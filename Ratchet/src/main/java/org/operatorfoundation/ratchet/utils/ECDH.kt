package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.Ratchet.NUM_BYTES_IN_KEY
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.Secret

object ECDH {

    /**
     * Perform Elliptic Curve Diffie-Hellman key exchange using BouncyCastle
     *
     * TODO: Per report, must also handle error state
     */
    fun perform(privateKey: PrivateKey, publicKey: EphemeralPublicKey): Secret
    {
        require(privateKey.isUsable() && publicKey.isUsable()) { "Expired key or keys" }

        val copyOfPrivateKey = PrivateKey(privateKey.copyBytes())
        val copyOfPublicKey = EphemeralPublicKey(publicKey.copyBytes())

        val copyOfPrivateKeyBytes: ByteArray = copyOfPrivateKey.copyBytes()
        val copyOfPublicKeyBytes: ByteArray = copyOfPublicKey.copyBytes()

        try {
            // BouncyCastle X25519 key agreement

            // Ensure we have the correct key sizes
            require(copyOfPrivateKeyBytes?.size == NUM_BYTES_IN_KEY) { "Private key must be $NUM_BYTES_IN_KEY bytes" }
            require(copyOfPublicKeyBytes?.size == NUM_BYTES_IN_KEY) { "Public key must be $NUM_BYTES_IN_KEY bytes" }

            // Perform X25519 scalar multiplication: shared_secret = privateKey * publicKey
            val sharedSecret = ByteArray(NUM_BYTES_IN_KEY)
            val successfulKeyAgreement = org.bouncycastle.math.ec.rfc7748.X25519.calculateAgreement(
                copyOfPrivateKeyBytes,
                0,
                copyOfPublicKeyBytes,
                0,
                sharedSecret,
                0
            )
            if (!successfulKeyAgreement) {
                sharedSecret.fill(0)
                throw SecurityException("Invalid key agreement")
            }
            return Secret(sharedSecret)
        }
        catch(e: SecurityException) {
            // TODO: Handle renegotiation of handshake
            throw e
        }
        catch(e: Exception) {
            throw e // TODO: Throw specific exception requiring renegotiation of handshake?
        }
        finally {
            copyOfPublicKeyBytes?.fill(0)
            copyOfPrivateKeyBytes?.fill(0)
        }
    }

}