package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.secure.SecureKey


/**
 * Private key
 *
 * Can represent the root key in the double ratchet algorithm, used to derive chain keys, as well as the
 * ECDHE private key for the internal rotation.
 *
 */
class PrivateKey(bytes: ByteArray): SecureKey(bytes.copyOf())
{

}

