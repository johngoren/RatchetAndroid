package org.operatorfoundation.ratchet.models

class SingleUseRatchetState(private val newRatchetState: RatchetState): AutoCloseable {

    var isDestroyed: Boolean = false

    private val _ratchetState: RatchetState

    init {
        _ratchetState = newRatchetState.copy()
        newRatchetState.close() // TODO: Check everything that we need survives.
    }

    fun use(block: (RatchetState) -> Unit) {
        check(!isDestroyed) { "Tried to use a ratchet state that has been destroyed" }
        block(_ratchetState)
    }

    override fun close() {
        _ratchetState.close()
    }

}