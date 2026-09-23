package org.operatorfoundation.ratchet.models.keys

import org.operatorfoundation.ratchet.models.keys.restriction.RestrictedKey

class Secret(bytes: ByteArray): RestrictedKey(bytes) {
}