package org.operatorfoundation.ratchet.models.keys.secure

import androidx.annotation.VisibleForTesting
import androidx.core.util.TimeUtils
import org.operatorfoundation.ratchet.Config
import org.operatorfoundation.ratchet.Config.NUM_BYTES_IN_KEY

open class SecureKey(keyBytes: ByteArray, val createdAt: Long = System.currentTimeMillis(), val lifespanHours: Int = Config.LIFESPAN_DEFAULT_HOURS): AutoCloseable {
    private var isDestroyed: Boolean = false
    private val isExpired: Boolean
        get() {
            val elapsedMs = System.currentTimeMillis() - createdAt
            return elapsedMs > (lifespanHours * 3600000)
        }

    private val _keyBytes: ByteArray

    init {
        require(keyBytes.size == NUM_BYTES_IN_KEY) {
            "AES-256 key must be $NUM_BYTES_IN_KEY bytes"
        }
        _keyBytes = keyBytes.copyOf()
    }

    fun consume(block: (ByteArray)->Unit) {
        check(!isDestroyed) { getMessageDescribingKeyDestruction() }
        check(!isExpired) { getMessageDescribingExpiredKey() }

        if (!isDestroyed) {
            block(_keyBytes)
        }
        close()
    }

    fun copyBytes(): ByteArray {
        check(!isDestroyed) { getMessageDescribingKeyDestruction() }
        return _keyBytes.copyOf()
    }

    override fun close() {
        if (!isDestroyed) {
            _keyBytes.fill(0)
            isDestroyed = true
        }
    }

    override fun toString(): String {
        return "Key" + if (isDestroyed) " ***destroyed*** " else " redacted for security"
    }

    override fun equals(other: Any?): Boolean
    {
        throw SecurityException("Equality operations have been disabled for security")
    }

    override fun hashCode(): Int
    {
        throw SecurityException("Hash codes have been disabled for security")
    }

    private fun getMessageDescribingKeyDestruction(): String {
        return "Key ${this.javaClass.name} has been destroyed "
    }

    private fun getMessageDescribingExpiredKey(): String {
        return "Key ${this.javaClass.name} has expired."
    }

    fun isUsable(): Boolean {
        return !isDestroyed
    }

    @VisibleForTesting
    val bytesForTesting: ByteArray
        get() {
            check(!isDestroyed) { getMessageDescribingKeyDestruction() }
            return _keyBytes.copyOf()
        }
}