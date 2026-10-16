package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.secure.SecureKey

class Secret(bytes: ByteArray): SecureKey(bytes) {
}