package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey

class Secret(bytes: ByteArray): SecureKey(bytes) {
}