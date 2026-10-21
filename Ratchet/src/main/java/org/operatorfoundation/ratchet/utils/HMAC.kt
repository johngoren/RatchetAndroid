package org.operatorfoundation.ratchet.utils

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val HMAC_ALGORITHM = "HmacSHA256"

object HMAC {

    /**
     * HMAC-SHA256 function
     */

    fun perform(key: ByteArray, data: ByteArray): ByteArray
    {
        val copyOfKeyBytes = key.copyOf()
        val copyOfDataBytes = data.copyOf()
        var secretKey: SecretKeySpec? = null

        return try {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            secretKey = SecretKeySpec(copyOfKeyBytes, HMAC_ALGORITHM)
            mac.init(secretKey)
            mac.doFinal(copyOfDataBytes)
        }
        catch(e: Exception) {
            throw e
        }
        finally {
            copyOfKeyBytes.fill(0)
            copyOfDataBytes.fill(0)
            secretKey?.destroy()
        }
    }
}