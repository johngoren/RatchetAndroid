package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey


/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
class PublicKey(bytes: ByteArray): SecureKey(bytes.copyOf())
{


}