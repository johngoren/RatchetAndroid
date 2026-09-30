package org.operatorfoundation.ratchet

import org.operatorfoundation.aes.AesGcmKey
import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SecureRatchetState
import org.operatorfoundation.ratchet.models.keys.PrivateKey
import org.operatorfoundation.ratchet.models.keys.Secret
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKey
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeyPair
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
        val outgoingEphemeralPublicKey: Curve25519PublicKey,
        val outgoingCounter: Int
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
    fun initRatchetState(
        localLongtermKeypair: SecureKeyPair,
        remoteLongtermPublicKey: Curve25519PublicKey,
        sessionId: ByteArray = ByteArray(16) // TODO: Require actual nonce
    ): SecureRatchetState
    {
        var newRatchetState: SecureRatchetState? = null

        val copyOfLongtermKeypair = localLongtermKeypair.copyOf()
        val copyOfRemoteLongtermPublicKey = remoteLongtermPublicKey.bytes.copyOf()
        val copyOfSessionId = sessionId.copyOf()
        var hkdfOutput: ByteArray? = null
        var sharedSecret: Secret? = null
        var newState: RatchetState? = null

        return try {
            require(copyOfSessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Invalid length of sessionID" }

            copyOfLongtermKeypair.use { localKeypairPeek ->

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                sharedSecret = ecdh(PrivateKey(localKeypairPeek.privateKey.bytes), remoteLongtermPublicKey)
                hkdfOutput = performHKDFtoDeriveRootKeyMaterial(
                    sharedSecret,
                    getInfo(KeyContext.RootKey.INFOPREFIX, copyOfSessionId.copyOf())
                )

                // Return initial state with defaults for optional fields
                newState = RatchetState(
                    localLongtermKeypair = copyOfLongtermKeypair,
                    remoteLongtermPublicKey = Curve25519PublicKey(copyOfRemoteLongtermPublicKey.copyOf()),
                    rootKey = RootKey.fromHKDF(hkdfOutput),
                    sessionId = copyOfSessionId.copyOf()
                )
                newRatchetState = SecureRatchetState(newState)
            }
            newRatchetState!!
        }
        catch(e: Exception) {
            newState?.close()
            invalidateAllState(localLongtermKeypair, remoteLongtermPublicKey)
            error(ERROR_MESSAGE_NEW_HANDSHAKE_REQUIRED)
        }
        finally {
            copyOfLongtermKeypair.close()
            copyOfRemoteLongtermPublicKey.fill(0)
            copyOfSessionId.fill(0)
            sharedSecret?.close()
            hkdfOutput?.fill(0)
        }
    }


    // ========== Advancing the ratchet, with or without new ephemeral keys ==========

    /**
     * Advances the ratchet _with_ new ephemeral keys (DH ratchet step).
     * This should be called when receiving a message with a new public key.
     *
     * The local ephemeral keypair is either a newly-generated ephemeral keypair
     * or (when the receiver has not yet sent a message) a key derived from her
     * longterm private key.
     *
     * @param oldState The current ratchet state
     * @param ephemeralKeypair Optional ECDH keys, not present at beginning of Bob's chat
     * @param remotePublicKey New remote ephemeral public key
     * @return The updated ratchet state
     */
    fun ratchetInternalWithNewKey(
        oldState: SecureRatchetState,
        ephemeralKeypair: SecureKeyPair?,
        remotePublicKey: Curve25519PublicKey        // Incoming ephemeral PK
    ): SecureRatchetState
    {
        var copyOfLocalLongtermKeypair: SecureKeyPair? = null
        var copyOfLocalLongtermPrivateKey: SecureKey? = null
        var copyOfRemotePublicKey: Curve25519PublicKey? = null
        var copyOfOldRootKey: SecureKey? = null
        var copyOfSessionId: ByteArray? = null
        var messageNum: Int? = null
        var sharedSecret: Secret? = null
        var hkdfOutput: ByteArray? = null
        var hmacOutput: ByteArray? = null
        var localKeyForECDH: PrivateKey? = null

        return try {
            oldState.use { oldStatePeek ->
                oldStatePeek.apply {
                    copyOfLocalLongtermKeypair = localLongtermKeypair.copyOf()
                    copyOfRemotePublicKey = Curve25519PublicKey(remotePublicKey.bytes.copyOf())
                    copyOfOldRootKey = RootKey(rootKey.bytes)
                    copyOfSessionId = sessionId
                    messageNum = messageNumber
                }
            }

            require(copyOfLocalLongtermKeypair != null) { "No copy available of local longterm keypair" }
            require(copyOfRemotePublicKey != null) { "No copy of remote public key" }
            require(copyOfSessionId != null) { "No copy of session ID" }
            require(copyOfOldRootKey != null) { "No copy of old root key " }
            require(messageNum != null) { "No copy of message number " }

            // Agnostic to whether it is a true ephemeral key or a fallback key
            if (ephemeralKeypair != null) {
                ephemeralKeypair.use { localEphemeralKeypairPeek ->
                    localKeyForECDH =
                        PrivateKey(localEphemeralKeypairPeek.privateKey.bytes.copyOf())
                }
            }
            else {
                copyOfLocalLongtermKeypair.use { copyOfLocalLongtermKeypairPeek ->
                    copyOfLocalLongtermPrivateKey =
                        SecureKey(copyOfLocalLongtermKeypairPeek.privateKey.bytes.copyOf())
                    copyOfLocalLongtermPrivateKey.use { privateKey ->
                        localKeyForECDH = deriveKeyFromLocalLongtermPrivateKey(
                            PrivateKey(privateKey),
                            getInfo(
                                KeyContext.RootKey.INFOPREFIX, copyOfSessionId
                            )
                        )
                    }
                }
            }

            require(localKeyForECDH != null) { "Could not find material for local ephemeral keypair " }

            // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
            sharedSecret = ecdh(localKeyForECDH, remotePublicKey)

            val newSharedKey = SharedKey.fromECDH(sharedSecret)

            // Derive new root and chain keys: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
            hkdfOutput = performHKDFtoGetRootAndChainKeyMaterial(
                copyOfOldRootKey.bytes,
                sharedSecret,
                getInfo(KeyContext.ChainKey.INFOPREFIX, copyOfSessionId)
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
                localEphemeralKeypair = ephemeralKeypair,
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

            oldState.close()
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
                    performHMAC(oldState.chainKey.bytes.copyOf(), newMessageNumber.toString().toByteArray())
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
            oldState.close()
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

        val newEphemeralKeypair = generateEphemeralKeypair()

        var remoteKey: Curve25519PublicKey? = null

        return try {
            oldState.use { oldState ->
                remoteKey = oldState.remoteEphemeralPublicKey ?: oldState.remoteLongtermPublicKey
                ratchetInternalWithNewKey(
                    oldState=SecureRatchetState(oldState),
                    ephemeralKeypair = newEphemeralKeypair.copyOf(),
                    remotePublicKey = Curve25519PublicKey(remoteKey.bytes.copyOf()))
                .use { newState ->
                    // TODO: Make this happen in RatchetInternal, based on some flag
                    val newCounter = oldState.monotonicCounterOutgoing + 1
                    newState.monotonicCounterOutgoing = newCounter

                    val newRatchetState = SecureRatchetState(newState)
                    result = RatchetSendResult(
                        newRatchetState,
                        newEphemeralKeypair.publicKey,
                        newCounter
                    )
                }
        }
        result ?: throw Exception("Null ratchet send result")
        }
        catch(e: Exception) {
            throw e             // TODO: Error handling
        }
        finally {
            newEphemeralKeypair.close()
            remoteKey?.bytes?.fill(0)
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
    fun ratchetForReceive(oldStateSecure: SecureRatchetState, incomingEphemeralPublicKey: Curve25519PublicKey, incomingCounter: Int? = null): SecureRatchetState {
        var newRatchetState: SecureRatchetState? = null
        var localEphemeralKeypair: SecureKeyPair? = null


        return try {
            oldStateSecure.use { oldStatePeek ->

                // TODO: Support counter overflow

                incomingCounter?.also {
                    if (it <= oldStatePeek.monotonicCounterIncoming) {
                        throw SecurityException("ECDH public key was not guaranteed to be new; counter value was too low")
                    }
                }


                localEphemeralKeypair = oldStatePeek.localEphemeralKeypair

                val resultingRatchetState = ratchetInternalWithNewKey(
                    oldState = oldStateSecure,
                    ephemeralKeypair = localEphemeralKeypair,
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
            localEphemeralKeypair?.close()
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
            aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes.copyOf())

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
            aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes.copyOf())

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
            aesKey?.bytes?.fill(0)
            decryptedBytes?.fill(0)
        }
    }


    // ========== Fundamental operations ==========

    private const val HMAC_ALGORITHM = "HmacSHA256"

    /**
     * Perform Elliptic Curve Diffie-Hellman key exchange using BouncyCastle
     *
     * TODO: Per report, must also handle error state
     */
    private fun ecdh(privateKey: PrivateKey, publicKey: Curve25519PublicKey): Secret
    {
        var copyOfPrivateKeyBytes: ByteArray? = null
        val publicKeyBytes = publicKey.bytes.copyOf()

        privateKey.use { privateKeyPeek ->
            copyOfPrivateKeyBytes = privateKeyPeek.copyOf()
        }

        return try {
            // BouncyCastle X25519 key agreement

            // Ensure we have the correct key sizes
            require(copyOfPrivateKeyBytes?.size == NUM_BYTES_IN_KEY) { "Private key must be $NUM_BYTES_IN_KEY bytes" }
            require(publicKeyBytes.size == NUM_BYTES_IN_KEY) { "Public key must be $NUM_BYTES_IN_KEY bytes" }

            // Perform X25519 scalar multiplication: shared_secret = privateKey * publicKey
            val sharedSecret = ByteArray(NUM_BYTES_IN_KEY)
            val successfulKeyAgreement = org.bouncycastle.math.ec.rfc7748.X25519.calculateAgreement(
                copyOfPrivateKeyBytes,
                0,
                publicKeyBytes,
                0,
                sharedSecret,
                0
            )
            if (!successfulKeyAgreement) {
                sharedSecret.fill(0)
                throw SecurityException("Invalid key agreement")
            }
            return Secret(sharedSecret)
        }
        catch(e: SecurityException) {
            // TODO: Handle renegotiation of handshake
            throw e
        }
        catch(e: Exception) {
            throw e // TODO: Throw specific exception requiring renegotiation of handshake?
        }
        finally {
            publicKeyBytes.fill(0)
            copyOfPrivateKeyBytes?.fill(0)
        }
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

    private fun performHKDFtoDeriveRootKeyMaterial(sharedSecret: Secret, info: ByteArray): ByteArray {
        var newOutput: ByteArray? = null
        val salt = (KeyContext.RootKey.SALT).toByteArray(Charsets.UTF_8)

        // TODO: Enforce proper secret size inside sharedSecret.

        return try {
            sharedSecret.use { sharedKey ->
                // HKDF-Extract: PRK = HMAC(salt=sharedSecret.bytes, ikm=sharedKey)
                val prk = performHMAC(salt, sharedKey)

                // HKDF-Expand: Generate 32-bytes

                newOutput = performHMAC(prk, info + byteArrayOf(0x01))
            }
            newOutput ?: throw Exception("Something went wrong")
        }
        catch(e: Exception) {
            throw e
        }
    }

    /**
     * Before any user has sent a message, no ECDH has happened yet, so we fall back to a key
     * derived from the longterm private key.
     */

    private fun deriveKeyFromLocalLongtermPrivateKey(securePrivateKey: PrivateKey, info: ByteArray): PrivateKey {
        var newOutput: ByteArray? = null
        var copyOfPrivateKeyBytes: ByteArray? = null

        return try {
            securePrivateKey.use { privateKey ->
                copyOfPrivateKeyBytes = privateKey.copyOf()

                require(copyOfPrivateKeyBytes.size == NUM_BYTES_IN_KEY) { "Invalid number of bytes in key" }

                val salt = KeyContext.EphemeralKey.SALT.toByteArray(Charsets.UTF_8)
                val prk = performHMAC(salt, copyOfPrivateKeyBytes)
                newOutput = performHMAC(prk, info + byteArrayOf(0x01))
            }
            require(newOutput != null) { "HMAC output was null" }
            PrivateKey(newOutput.copyOf())
        }
        catch(e: Exception) {
            throw e
        }
        finally {
            copyOfPrivateKeyBytes?.fill(0)
            newOutput?.fill(0)
        }
    }


    /**
     * HMAC-SHA256 function
     */

    private fun performHMAC(key: ByteArray, data: ByteArray): ByteArray
    {
        val copyOfKeyBytes = key.copyOf()
        val copyOfDataBytes = data.copyOf()
        var secretKey: SecretKeySpec? = null

        return try {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            secretKey = SecretKeySpec(copyOfKeyBytes, HMAC_ALGORITHM)
            mac.init(secretKey)
            mac.doFinal(copyOfDataBytes)
        }
        catch(e: Exception) {
            throw e
        }
        finally {
            copyOfKeyBytes.fill(0)
            copyOfDataBytes.fill(0)
            // TODO: And destroy secret key?
        }
    }

    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): SecureKeyPair {
        return SecureKeyPair(MADH.generateKeypair())
    }

    private fun getInfo(prefix: String, sessionId: ByteArray): ByteArray {
        require(sessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Session nonce was wrong size "}

        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate((prefixBytes.size + sessionId.size))
            .put(prefixBytes)
            .put(sessionId)
            .array()

    }

    private fun invalidateAllState(localLongtermKeypair: SecureKeyPair, remotePublicKey: Curve25519PublicKey) {
        localLongtermKeypair.close()
        remotePublicKey.bytes.fill(0)
    }

    const val ERROR_MESSAGE_NEW_HANDSHAKE_REQUIRED = "Ratchet error. New handshake required."


}

object KeyContext {
    object RootKey {
        const val SALT = "SHOUT-v1-Salt-RootKey"
        const val INFOPREFIX = "SHOUT-ROOT"
    }

    object ChainKey {
        const val SALT = "SHOUT-v1-Salt-ChainKey" // TODO: Not needed because the salt IS the previous chain, right?
        const val INFOPREFIX = "SHOUT-CHAIN"
    }

    object EphemeralKey {
        const val SALT = "SHOUT-v1-Salt-Ephemeral"
        const val INFOPREFIX = "SHOUT-EPHEMERAL"
    }

}