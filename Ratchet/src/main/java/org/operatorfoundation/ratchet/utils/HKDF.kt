package org.operatorfoundation.ratchet.utils

import org.operatorfoundation.ratchet.models.keys.Secret

object HKDF {
    /**
     * HKDF (HMAC-based Key Derivation Function) implementation
     * Returns 64 bytes (32 for root key, 32 for chain key)
     */

    fun forRootAndChainMaterial(
        oldRootKey: ByteArray,
        sharedSecret: Secret,
        info: ByteArray
    ): ByteArray {
        val copyOfSharedSecret = Secret(sharedSecret.copyBytes())
        var result: ByteArray? = null

        var prk: ByteArray? = null
        var t1: ByteArray? = null
        var t2: ByteArray? = null

        try {
            copyOfSharedSecret.consume { sharedKey ->
                // HKDF-Extract: PRK = HMAC(salt=oldRootKey, ikm=sharedKey)
                prk = HMAC.perform(oldRootKey, sharedKey)

                // HKDF-Expand: Generate 64 bytes (32 for new root key, 32 for chain key)
                t1 = HMAC.perform(prk, info + byteArrayOf(0x01))
                t2 = HMAC.perform(prk, t1 + info + byteArrayOf(0x02))
                result = t1 + t2

            }
            // Concatenate to return full 64 bytes
            return result?.copyOf() ?: throw Exception("Something went wrong")
        }
        catch(e: Exception) {
            throw SecurityException(e.message)
        }
        finally {
            prk?.fill(0)
            t1?.fill(0)
            t2?.fill(0)
            result?.fill(0)
        }
    }

    fun forRootKeyMaterial(sharedSecret: Secret, info: ByteArray): ByteArray {
        var newOutput: ByteArray? = null
        val salt = (ContextField.RootKey.SALT).toByteArray(Charsets.UTF_8)
        var prk: ByteArray? = null

        // TODO: Enforce proper secret size inside sharedSecret.

        return try {
            sharedSecret.consume { sharedKey ->
                // HKDF-Extract: PRK = HMAC(salt=sharedSecret.bytes, ikm=sharedKey)
                prk = HMAC.perform(salt, sharedKey)

                // HKDF-Expand: Generate 32-bytes
                newOutput = HMAC.perform(prk, info + byteArrayOf(0x01))
            }
            newOutput?.copyOf() ?: throw Exception("Something went wrong")
        } catch (e: Exception) {
            throw e
        }
        finally {
            prk?.fill(0)
            newOutput?.fill(0)
        }
    }

}