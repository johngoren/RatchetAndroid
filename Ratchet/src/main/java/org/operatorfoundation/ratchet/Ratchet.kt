package org.operatorfoundation.ratchet

import org.bouncycastle.util.encoders.UTF8
import org.operatorfoundation.aes.AesGcmKey
import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeypair
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Main API for the Double Ratchet algorithm.
 *
 * The Double Ratchet provides forward secrecy and break-in recovery for
 * asynchronous messaging by combining a Diffie-Hellman ratchet with a
 * symmetric key ratchet.
 *
 *
 */

object Ratchet
{
    const val NUM_BYTES_IN_KEY = 32
    const val NUM_BYTES_IN_SESSION_NONCE = 16   // TODO: Decide on length

    class RatchetSendResult(
        val state: SecureRatchetState,
        val outgoingEphemeralPublicKey: Curve25519PublicKey
    )

    // ========== Creating a new ratchet state ==========

    /**
     * Creates a new ratchet state from long-term keys
     * This initializes the double ratchet algorithm.
     *
     * According to the spec:
     * R_0 = ECDH(priv_a0, k_b0)
     *
     * @param localLongtermKeypair The local party's long-term key pair
     * @param remoteLongtermPublicKey The remote party's long-term public key
     * @return The initial ratchet state
     */
    fun newRatchetState(
        localLongtermKeypair: SecureKeypair,
        remoteLongtermPublicKey: Curve25519PublicKey,
        sessionId: ByteArray = ByteArray(16) // TODO: Require actual nonce
    ): SecureRatchetState
    {
        var newRatchetState: SecureRatchetState? = null

        val copyOfLongtermKeypair = localLongtermKeypair.deepCopy()
        val copyOfRemoteLongtermPublicKey = remoteLongtermPublicKey.copy() // TODO: Check if actual copy.
        var hkdfOutput: ByteArray? = null
        var sharedSecret: Secret? = null

        return try {
            require(sessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Invalid length of sessionID" }

            copyOfLongtermKeypair.use { localKeypair ->

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                sharedSecret = ecdh(localKeypair.privateKey, remoteLongtermPublicKey)
                hkdfOutput = performHKDFtoDeriveRootKeyMaterial(
                    KeyContext.RootKey.SALT.toByteArray(Charsets.UTF_8),
                    sharedSecret,
                    getInfoFieldForInitialRootKey(sessionId)
                )

                // Return initial state with defaults for optional fields
                val newState = RatchetState(
                    localLongtermKeypair = copyOfLongtermKeypair,
                    remoteLongtermPublicKey = Curve25519PublicKey(copyOfRemoteLongtermPublicKey.bytes),
                    rootKey = RootKey.fromHKDF(hkdfOutput),
                    sessionId = sessionId
                )
                newRatchetState = SecureRatchetState(newState)
            }
            newRatchetState!!
        }
        catch(e: Exception) {
            throw e // TODO: Throw specific handled errors.
        }
        finally {
            // Disabled for now because of tests
//            copyOfLongtermKeypair.close()
//            copyOfRemoteLongtermPublicKey.bytes.fill(0)
            sharedSecret?.close()
            hkdfOutput?.fill(0)
        }
    }


    // ========== Advancing the ratchet, with or without new ephemeral keys ==========

    /**
     * Advances the ratchet _with_ new ephemeral keys (DH ratchet step).
     * This should be called when receiving a message with a new public key.
     *
     * @param oldState The current ratchet state
     * @param remotePublicKey New remote ephemeral public key
     * @return The updated ratchet state
     */
    fun ratchetInternalWithNewKey(
        oldState: SecureRatchetState,
        longtermKeypair: SecureKeypair?,
        localEphemeralKeypair: SecureKeypair?,
        remotePublicKey: Curve25519PublicKey        // Incoming ephemeral PK
    ): SecureRatchetState
    {
        var copyOfLocalLongtermKeypair: SecureKeypair? = null
        var copyOfRemotePublicKey: Curve25519PublicKey? = null
        var copyOfOldRootKey: SecureKey? = null
        var copyOfSessionId: ByteArray? = null
        var messageNum: Int? = null
        var sharedSecret: Secret? = null
        var hkdfOutput: ByteArray? = null
        var hmacOutput: ByteArray? = null

        return try {
            oldState.use { oldStatePeek ->
                oldStatePeek.apply {
                    copyOfLocalLongtermKeypair = localLongtermKeypair.deepCopy()
                    copyOfRemotePublicKey = Curve25519PublicKey(remotePublicKey.bytes)
                    copyOfOldRootKey = RootKey(rootKey.copyBytes())
                    copyOfSessionId = sessionId
                    messageNum = messageNumber
                }
            }

            require(copyOfLocalLongtermKeypair != null) { "No copy available of local longterm keypair" }
            require(copyOfRemotePublicKey != null) { "No copy of remote public key" }
            require(copyOfSessionId != null) { "No copy of session ID" }
            require(copyOfOldRootKey != null) { "No copy of old root key " }
            require(messageNum != null) { "No copy of message number " }

            var localEphemeralPrivateKey: Curve25519PrivateKey? = null
            if (localEphemeralKeypair != null) {
                localEphemeralKeypair.use { localEphemeralKeypairPeek ->
                    localEphemeralPrivateKey = localEphemeralKeypairPeek.privateKey.copy()
                }
            } else {
                longtermKeypair?.use { longtermKeypairPeek ->
                    localEphemeralPrivateKey = deriveKeyFromLocalLongtermPrivateKey(
                        longtermKeypairPeek.privateKey,
                        getInfoFieldForBootstrapKey(copyOfSessionId)
                    )
                }
            }

            require(localEphemeralPrivateKey != null) { "Could not find material for local ephemeral keypair " }

            // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
            sharedSecret = ecdh(localEphemeralPrivateKey, remotePublicKey)
            val newSharedKey = SharedKey.fromECDH(sharedSecret)

            // Derive new root and chain keys: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
            hkdfOutput = performHKDFtoGetRootAndChainKeyMaterial(
                copyOfOldRootKey.bytes,
                sharedSecret,
                getInfoFieldForRatchet(copyOfSessionId)
            )
            val newRootKey = RootKey.fromHKDF(hkdfOutput)
            val newChainKey = ChainKey.fromHKDF(hkdfOutput)

            // Increment message number and derive message key: M_n = HMAC(C_n, n)
            val newMessageNumber = messageNum + 1
            hmacOutput =
                performHMAC(newChainKey.bytes, newMessageNumber.toString().toByteArray())
            val messageKey = MessageKey.fromHMAC(hmacOutput)

            val newState = RatchetState(
                localLongtermKeypair = copyOfLocalLongtermKeypair,
                remoteLongtermPublicKey = copyOfRemotePublicKey,
                rootKey = newRootKey,
                messageNumber = newMessageNumber,
                chainKey = newChainKey,
                sharedKey = newSharedKey,
                messageKey = messageKey,
                localEphemeralKeypair = longtermKeypair,
                remoteEphemeralPublicKey = remotePublicKey
            )
            SecureRatchetState(newState)
        }
        catch(e: Exception) {
            throw e
        } finally {
            copyOfOldRootKey?.bytes?.fill(0)
            sharedSecret?.bytes?.fill(0)
            hkdfOutput?.fill(0)
            hmacOutput?.fill(0)
        }
    }


    /**
     * Advances the ratchet without new keys (symmetric ratchet step).
     * This should be called when sending/receiving multiple messages
     * without a key change (consecutive messages, same sender).
     *
     * @param oldState The current ratchet state
     * @return The updated ratchet state with new chain and message keys
     */
    fun symmetricRatchetWithoutIncomingKey(oldState: SecureRatchetState): SecureRatchetState
    {
        var nextRatchetState: SecureRatchetState? = null
        var chainHmacOutput: ByteArray? = null
        var messageHmacOutput: ByteArray? = null

        return try {
            oldState.use { oldState ->

                // Ensure we have a chain key to work with
                requireNotNull(oldState.chainKey) { "Cannot ratchet without a chain key. Call ratchetWithNewKey first." }

                // Increment message number
                val newMessageNumber = oldState.messageNumber + 1

                // Derive new chain key: C_n = HMAC(C_{n-1}, n)
                chainHmacOutput =
                    performHMAC(oldState.chainKey.bytes, newMessageNumber.toString().toByteArray())
                val newChainKey = ChainKey.fromHMAC(chainHmacOutput)

                // Derive new message key: M_n = HMAC(C_n, n)
                messageHmacOutput =
                    performHMAC(newChainKey.bytes, newMessageNumber.toString().toByteArray())

                val newState = oldState.deepCopy(
                    messageNumber = newMessageNumber,
                    chainKey = newChainKey,
                    messageKey = MessageKey.fromHMAC(messageHmacOutput)
                )
                nextRatchetState = SecureRatchetState(newState)
            }

            nextRatchetState ?: throw Exception("Null ratchet state")
        }
        catch(e: Exception) {
            throw e // TODO: More specific error-handling
        }
        finally {
            chainHmacOutput?.fill(0)
            messageHmacOutput?.fill(0)
        }
    }


    // ========== Sending and receiving ==========

    /**
     * Ratchet for sending a message.
     * Generates a new ephemeral keypair and uses the current remote public key.
     *
     * @param oldState The current ratchet state
     * @return Result containing the new state and the ephemeral public key to send
     */
    fun ratchetForSend(oldState: SecureRatchetState): RatchetSendResult
    {
        var result: RatchetSendResult? = null

        return try {
            oldState.use { oldState ->
                val newSecureKeypair = generateEphemeralKeypair()
                    val remoteKey = oldState.remoteEphemeralPublicKey ?: oldState.remoteLongtermPublicKey
                    ratchetInternalWithNewKey(
                        oldState=SecureRatchetState(oldState),
                        longtermKeypair = null,
                        localEphemeralKeypair = newSecureKeypair,
                        remotePublicKey = remoteKey)
                    .use { newState ->
                        val newRatchetState = SecureRatchetState(newState)
                        result = RatchetSendResult(newRatchetState, newSecureKeypair.publicKey)
                    }
            }
            result ?: throw Exception("Null ratchet send result")
        }
        catch(e: Exception) {
            throw e             // TODO: Error handling
        }
    }

    /**
     * Ratchet for receiving a message.
     * Uses the current local keypair with the sender's new ephemeral public key.
     *
     * @param oldState The current ratchet state
     * @param incomingEphemeralPublicKey The ephemeral public key received from the sender
     * @return The updated ratchet state
     */
    fun ratchetForReceive(oldStateSecure: SecureRatchetState, incomingEphemeralPublicKey: Curve25519PublicKey): SecureRatchetState {
        var newRatchetState: SecureRatchetState? = null

        return try {
            oldStateSecure.use { oldStatePeek ->

                val ephemeralKeypair = oldStatePeek.localEphemeralKeypair
                val fallbackToLongtermKeypair = if (ephemeralKeypair != null) {
                    null
                } else {
                    oldStatePeek.localLongtermKeypair
                }

                val resultingRatchetState = ratchetInternalWithNewKey(
                    oldState = oldStateSecure,
                    longtermKeypair = fallbackToLongtermKeypair,
                    localEphemeralKeypair = ephemeralKeypair,
                    remotePublicKey = incomingEphemeralPublicKey,
                )

                newRatchetState = resultingRatchetState
            }
            require(newRatchetState != null) { "Null ratchet state" }
            newRatchetState
        } catch(e: Exception) {
            throw e     // TODO: Error-handling
        }
        finally {

        }
    }


    // ========== Encrypting and decrypting ==========

    /**
     * Encrypts a plaintext message using the message key.
     * Uses AES-GCM for authenticated encryption.
     *
     * @param key The message key to use for encryption
     * @param plaintext The plaintext message to encrypt
     * @return The ciphertext
     */
    fun encrypt(key: MessageKey, plaintext: PlaintextMessage): Ciphertext
    {
        var copyOfPlaintextBytes: ByteArray? = null
        var aesKey: AesGcmKey? = null

        return try {
            // Serialize the plaintext message to bytes
            copyOfPlaintextBytes = plaintext.toBytes()

            // Create AES-GCM key from the message key
            aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes)

            // Create cipher and encrypt
            val cipher = org.operatorfoundation.aes.AesCipher()
            return cipher.encrypt(aesKey, copyOfPlaintextBytes)
        }
        catch(e: Exception) {
            throw e // TODO: Error handling
        }
        finally {
            copyOfPlaintextBytes?.fill(0)
            aesKey?.bytes?.fill(0)
        }
    }

    /**
     * Decrypts a ciphertext message using the message key.
     * Uses AES-GCM for authenticated decryption.
     *
     * @param key The message key to use for decryption
     * @param ciphertext The ciphertext to decrypt
     * @return The decrypted plaintext message
     */
    fun decrypt(key: MessageKey, ciphertext: Ciphertext): PlaintextMessage?
    {
        var aesKey: AesGcmKey? = null
        var decryptedBytes: ByteArray? = null

        return try {

            // Create AES-GCM key from the message key
            aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes)

            // Create cipher and decrypt
            val cipher = org.operatorfoundation.aes.AesCipher()
            decryptedBytes = cipher.decrypt(aesKey, ciphertext)

            // Deserialize the plaintext message
            PlaintextMessage.fromBytes(decryptedBytes.copyOf())
        }
        catch(e: IllegalArgumentException) {
            return null
        }
        finally {
            decryptedBytes?.fill(0)
        }
    }


    // ========== Fundamental operations ==========


    private const val HMAC_ALGORITHM = "HmacSHA256"

    /**
     * Perform Elliptic Curve Diffie-Hellman key exchange using BouncyCastle
     */
    private fun ecdh(privateKey: Curve25519PrivateKey, publicKey: Curve25519PublicKey): Secret
    {
        // BouncyCastle X25519 key agreement
        val privateKeyBytes = privateKey.bytes
        val publicKeyBytes = publicKey.bytes

        // Ensure we have the correct key sizes
        require(privateKeyBytes.size == NUM_BYTES_IN_KEY) { "Private key must be $NUM_BYTES_IN_KEY bytes" }
        require(publicKeyBytes.size == NUM_BYTES_IN_KEY) { "Public key must be $NUM_BYTES_IN_KEY bytes" }

        // Perform X25519 scalar multiplication: shared_secret = privateKey * publicKey
        val sharedSecret = ByteArray(NUM_BYTES_IN_KEY)
        org.bouncycastle.math.ec.rfc7748.X25519.scalarMult(
            privateKeyBytes,
            0,
            publicKeyBytes,
            0,
            sharedSecret,
            0
        )
        return Secret(sharedSecret)
    }

    /**
     * HKDF (HMAC-based Key Derivation Function) implementation
     * Returns 64 bytes (32 for root key, 32 for chain key)
     */


    private fun performHKDFtoGetRootAndChainKeyMaterial(oldRootKey: ByteArray, sharedSecret: Secret, info: ByteArray): ByteArray
    {
        var result: ByteArray? = null

        sharedSecret.use { sharedKey ->
            // HKDF-Extract: PRK = HMAC(salt=oldRootKey, ikm=sharedKey)
            val prk = performHMAC(oldRootKey, sharedKey)

            // HKDF-Expand: Generate 64 bytes (32 for new root key, 32 for chain key)
            val t1 = performHMAC(prk, info + byteArrayOf(0x01))
            val t2 = performHMAC(prk, t1 + info + byteArrayOf(0x02))
            result = t1 + t2

        }
        // Concatenate to return full 64 bytes
        return result ?: throw Exception("Something went wrong")
    }

    private fun performHKDFtoDeriveRootKeyMaterial(salt: ByteArray? = null, sharedSecret: Secret, info: ByteArray): ByteArray {
        var newOutput: ByteArray? = null
        val salt = (KeyContext.RootKey.SALT).toByteArray(Charsets.UTF_8)

        // TODO: Enforce proper secret size inside sharedSecret.

        sharedSecret.use { sharedKey ->
            // HKDF-Extract: PRK = HMAC(salt=sharedSecret.bytes, ikm=sharedKey)
            val prk = performHMAC(salt, sharedKey)

            // HKDF-Expand: Generate 32-bytes

            val t1 = performHMAC(prk, info + byteArrayOf(0x01))
            newOutput = t1
        }

        return newOutput ?: throw Exception("Something went wrong")
    }

    /**
     * Before any user has sent a message, no ECDH has happened yet, so we fall back to a key
     * derived from the longterm private key.
     */

    private fun deriveKeyFromLocalLongtermPrivateKey(longtermPrivateKey: Curve25519PrivateKey, info: ByteArray): Curve25519PrivateKey {
        require(longtermPrivateKey.bytes.size == NUM_BYTES_IN_KEY) { "Invalid number of bytes in key"}

        var newOutput: ByteArray? = null
        val salt = KeyContext.EphemeralKey.SALT.toByteArray(Charsets.UTF_8)
        val prk = performHMAC(salt, longtermPrivateKey.bytes)

        // HKDF-Expand: Generate 32 bytes

        val infoBytes = info
        newOutput = performHMAC(prk, infoBytes + byteArrayOf(0x01)) // TODO: Why are we adding this
        val newKey = Curve25519PrivateKey(newOutput )
        return newKey
    }


    /**
     * HMAC-SHA256 function
     */
    private fun performHMAC(key: ByteArray, data: ByteArray): ByteArray
    {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKey = SecretKeySpec(key, HMAC_ALGORITHM)
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): SecureKeypair {
        return SecureKeypair(MADH.generateKeypair())
    }

    private fun getInfoArray(prefix: String, sessionId: ByteArray): ByteArray {
        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate((prefixBytes.size + sessionId.size))
            .put(prefixBytes)
            .put(sessionId)
            .array()

    }
    // Binds initial root key to session

    private fun getInfoFieldForInitialRootKey(sessionId: ByteArray): ByteArray {
        require(sessionId.size == 16) { "Invalid number of bytes in session ID" }

        return getInfoArray(KeyContext.RootKey.INFOPREFIX, sessionId)
    }

    private fun getInfoFieldForRatchet(sessionId: ByteArray): ByteArray {
        require(sessionId.size == 16) { "Invalid number of bytes in session ID" }

        return getInfoArray(KeyContext.ChainKey.INFOPREFIX, sessionId)
    }

    // TODO: Check if this info value will trip us up in this situation,
    // as it is sharing a domain with the other key in Operator's MADH library
    // but uses a different context. Does it matter? Maybe not.

    private fun getInfoFieldForBootstrapKey(sessionId: ByteArray): ByteArray {
        require(sessionId.size == 16) { "Invalid number of bytes in session ID" }

        return getInfoArray(KeyContext.EphemeralKey.INFOPREFIX, sessionId)
    }

}

object KeyContext {
    object RootKey {
        val SALT = "SHOUT-v1-Salt-RootKey"
        val INFOPREFIX = "SHOUT-ROOT"
    }

    object ChainKey {
        val SALT = "SHOUT-v1-Salt-ChainKey"
        val INFOPREFIX = "SHOUT-CHAIN"
    }

    object EphemeralKey {
        val SALT = "SHOUT-v1-Salt-Ephemeral"
        val INFOPREFIX = "SHOUT-EPHEMERAL"
    }

}