package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.secure.SecureKey


/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
class PublicKey(bytes: ByteArray, val counter: Int): SecureKey(bytes.copyOf())
