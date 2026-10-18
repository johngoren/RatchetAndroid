package org.operatorfoundation.ratchet.models

//
//class SecureRatchetState(containedState: RatchetState): AutoCloseable {
//
//    var isDestroyed: Boolean = false
//
//    private val _ratchetState: RatchetState
//
//    init {
//        _ratchetState = containedState.copy()
//    }
//
//    // TODO: Should make copies here in the this() block, right?
//
//
//    fun consume(block: (RatchetState) -> Unit) {
//        check(!isDestroyed) { "Tried to use a ratchet state that has been destroyed" }
//        block(_ratchetState)
//    }
//
//    override fun close() {
//        isDestroyed = true
//        _ratchetState.close()
//    }
//
//}