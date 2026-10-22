package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.Config.NUM_BYTES_IN_KEY
import org.operatorfoundation.ratchet.RedoHandshakeException
import org.operatorfoundation.ratchet.models.keys.EphemeralPublicKey
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.Secret

object ECDH {

    /**
     * Perform Elliptic Curve Diffie-Hellman key exchange using BouncyCastle
     *
     */

    fun perform(privateKey: PrivateKey, publicKey: EphemeralPublicKey): Secret
    {
        require(privateKey.isUsable() && publicKey.isUsable()) { "** Expired key** " }

        val copyOfPrivateKey = PrivateKey(privateKey.copyBytes())
        val copyOfPublicKey = EphemeralPublicKey(publicKey.copyBytes())

        val copyOfPrivateKeyBytes: ByteArray = copyOfPrivateKey.copyBytes()
        val copyOfPublicKeyBytes: ByteArray = copyOfPublicKey.copyBytes()

        var sharedSecret: ByteArray? = null

        try {
            // BouncyCastle X25519 key agreement

            require(copyOfPrivateKeyBytes.size == NUM_BYTES_IN_KEY) { "Private key must be $NUM_BYTES_IN_KEY bytes" }
            require(copyOfPublicKeyBytes.size == NUM_BYTES_IN_KEY) { "Public key must be $NUM_BYTES_IN_KEY bytes" }

            // Perform X25519 scalar multiplication: shared_secret = privateKey * publicKey
            sharedSecret = ByteArray(NUM_BYTES_IN_KEY)

            // The RFC 7748 check guards against the threat of the invalid zeroes array
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
                throw SecurityException("Unsuccessful key agreement. Possibly bad peer key.")
            }
            return Secret(sharedSecret.copyOf())
        }
        catch(e: SecurityException) {
            throw RedoHandshakeException(e.message ?: "An error occurred during ECDH")
        }
        catch(e: Exception) {
            throw e
        }
        finally {
            copyOfPublicKeyBytes.fill(0)
            copyOfPrivateKeyBytes.fill(0)
            sharedSecret?.fill(0)
        }
    }
}