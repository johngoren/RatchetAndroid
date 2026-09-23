package org.operatorfoundation.ratchet.models


class SecureRatchetState(newRatchetState: RatchetState): AutoCloseable {

    var isDestroyed: Boolean = false

    private val _ratchetState: RatchetState

    init {
        _ratchetState = newRatchetState.deepCopy()
    }

    fun use(block: (RatchetState) -> Unit) {
        check(!isDestroyed) { "Tried to use a ratchet state that has been destroyed" }
        block(_ratchetState)
    }

    override fun close() {
        isDestroyed = true
        _ratchetState.close()
    }

}