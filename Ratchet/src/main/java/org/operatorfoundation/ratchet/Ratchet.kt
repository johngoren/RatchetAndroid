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
        val outgoingCounter: Int? = null,
        val numMessagesInSendingChain: Int? = null
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
        val copyOfRemoteLongtermPublicKey = Curve25519PublicKey(remoteLongtermPublicKey.bytes.copyOf())
        var copyOfLocalPrivateKey: PrivateKey? = null
        val copyOfSessionId = sessionId.copyOf()
        var hkdfOutput: ByteArray? = null
        var sharedSecret: Secret? = null
        var newState: RatchetState? = null

        return try {
            require(copyOfSessionId.size == NUM_BYTES_IN_SESSION_NONCE) { "Invalid length of sessionID" }

            copyOfLongtermKeypair.use { localKeypairPeek ->

                // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
                copyOfLocalPrivateKey = PrivateKey(localKeypairPeek.privateKey.bytes)
                sharedSecret = ecdh(copyOfLocalPrivateKey, copyOfRemoteLongtermPublicKey)

                hkdfOutput = performHKDFtoDeriveRootKeyMaterial(
                    sharedSecret,
                    getInfo(KeyContext.RootKey.INFOPREFIX, copyOfSessionId.copyOf())
                )

                // Return initial state with defaults for optional fields
                newState = RatchetState(
                    localLongtermKeypair = copyOfLongtermKeypair,
                    remoteLongtermPublicKey = copyOfRemoteLongtermPublicKey,
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
            copyOfRemoteLongtermPublicKey.bytes.fill(0)
            copyOfLocalPrivateKey?.close()
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
     * @param oldState The current ratchet state
     * @param localEphemeralKeypair ECDHE keys
     * @param incomingPublicKey New remote ephemeral public key
     * @return The updated ratchet state
     */

    // TODO: Defensive quality checks around all of these keys.
    // TODO: Understand better how we store or do not store keys in state.

    fun ratchetInternalWithNewEntropy(
        oldState: SecureRatchetState,
        localEphemeralKeypair: SecureKeyPair?,          // TODO: Safe to make this non-nullable?
        incomingPublicKey: Curve25519PublicKey        // Incoming ephemeral PK
    ): SecureRatchetState
    {
        var copyOfLocalLongtermKeypair: SecureKeyPair? = null
        var copyOfLocalEphemeralPrivateKey: ByteArray? = null
        var copyOfIncomingPublicKey: Curve25519PublicKey? = null
        var copyOfOldRootKey: SecureKey? = null
        var copyOfSessionId: ByteArray? = null
        var messageNum: Int? = null
        var sharedSecret: Secret? = null
        var hkdfOutput: ByteArray? = null
        var hmacOutput: ByteArray? = null

        return try {
            localEphemeralKeypair?.use { localECDHEPeek ->
                require(localECDHEPeek.privateKey.bytes.size == NUM_BYTES_IN_KEY) { "ECDHE key is wrong size "}
                copyOfLocalEphemeralPrivateKey = localECDHEPeek.privateKey.bytes.copyOf()
            }

            oldState.use { oldStatePeek ->
                oldStatePeek.apply {
                    copyOfLocalLongtermKeypair = localLongtermKeypair.copyOf()
                    copyOfIncomingPublicKey = Curve25519PublicKey(incomingPublicKey.bytes.copyOf())
                    copyOfOldRootKey = RootKey(rootKey.bytes)
                    copyOfSessionId = sessionId
                    messageNum = messageNumber
                }
            }

            // ** temporary workaround. Later we can ensure non-null **
            if (copyOfLocalEphemeralPrivateKey == null) {
                val newKeypair = MADH.generateKeypair()
                copyOfLocalEphemeralPrivateKey = newKeypair.privateKey.bytes

//                copyOfLocalLongtermKeypair!!.use { peek ->
//                    copyOfLocalEphemeralPrivateKey = peek.privateKey.bytes.copyOf()
//                }
            }
            // ** end temporary crutch **

            require(copyOfLocalLongtermKeypair != null) { "No copy available of local longterm keypair" }
            require(copyOfLocalEphemeralPrivateKey != null) { "No copy available of local ECDHE private key" }
            require(copyOfIncomingPublicKey != null) { "No copy of remote public key" }
            require(copyOfSessionId != null) { "No copy of session ID" }
            require(copyOfOldRootKey != null) { "No copy of old root key " }
            require(messageNum != null) { "No copy of message number " }



            // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
            sharedSecret = ecdh(PrivateKey(copyOfLocalEphemeralPrivateKey!!.copyOf()), copyOfIncomingPublicKey)
            val newSharedKey = SharedKey.fromECDH(sharedSecret)

            // Derive new root and chain keys:
            // was: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
            // now: (R_n, C_n) = HKDF(R_{n-1}, S_n, {info context binding the key to session and counter nonces})

            val contextBoundToSessionAndCounterNonces = getInfoWithCounter(KeyContext.ChainKey.INFOPREFIX, copyOfSessionId, messageNum)

            hkdfOutput = performHKDFtoGetRootAndChainKeyMaterial(
                copyOfOldRootKey.bytes,
                sharedSecret,
                contextBoundToSessionAndCounterNonces
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
                remoteLongtermPublicKey = copyOfIncomingPublicKey,
                rootKey = newRootKey,
                messageNumber = newMessageNumber,
                chainKey = newChainKey,
                sharedKey = newSharedKey,
                messageKey = messageKey,
                localEphemeralKeypair = localEphemeralKeypair,  // TODO: Check this!! And which one ends up in result!!
                remoteEphemeralPublicKey = incomingPublicKey
            )
            SecureRatchetState(newState)
        }
        catch(e: Exception) {
            throw e
        } finally {
            copyOfOldRootKey?.bytes?.fill(0)
            copyOfIncomingPublicKey?.bytes?.fill(0)
            copyOfLocalEphemeralPrivateKey?.fill(0)
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
    fun symmetricRatchet(oldState: SecureRatchetState): SecureRatchetState
    {
        var nextRatchetState: SecureRatchetState? = null
        var copyOfOldChainKey: ByteArray? = null
        var chainHmacOutput: ByteArray? = null
        var messageHmacOutput: ByteArray? = null

        return try {
            oldState.use { oldState ->

                // Ensure we have a chain key to work with
                requireNotNull(oldState.chainKey) { "Cannot ratchet without a chain key. Call ratchetInternalWithNewKey first." }

                copyOfOldChainKey = oldState.chainKey.bytes.copyOf()

                // Increment message number
                val newMessageNumber = oldState.messageNumber + 1

                // Derive new chain key: C_n = HMAC(C_{n-1}, n)
                chainHmacOutput = performHMAC(
                    copyOfOldChainKey,
                    newMessageNumber.toString().toByteArray()
                )
                val newChainKey = ChainKey.fromHMAC(chainHmacOutput)

                // Derive new message key: M_n = HMAC(C_n, n)
                messageHmacOutput = performHMAC(
                    key=newChainKey.bytes,
                    data=newMessageNumber.toString().toByteArray()
                )

                val newState = oldState.copy(
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
            copyOfOldChainKey?.fill(0)
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
                remoteKey = oldState.remoteEphemeralPublicKey ?: MADH.generateKeypair().publicKey   // TODO: Temporary fix?
                ratchetInternalWithNewEntropy(
                    oldState=SecureRatchetState(oldState),
                    localEphemeralKeypair = newEphemeralKeypair.copyOf(),
                    incomingPublicKey = Curve25519PublicKey(remoteKey.bytes.copyOf()))
                .use { newState ->
                    val newCounter = oldState.counterPreviousSentKey + 1
                    newState.counterPreviousSentKey = newCounter

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
            throw e             // TODO: Granular error handling
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
     * @param incomingCounter The message counter number that was received from the sender
     * @return The updated ratchet state
     */
    fun ratchetForReceive(oldStateSecure: SecureRatchetState, incomingEphemeralPublicKey: Curve25519PublicKey, incomingCounter: Int? = null): SecureRatchetState {
        var newRatchetState: SecureRatchetState? = null
        var localEphemeralKeypair: SecureKeyPair? = null

        return try {
            oldStateSecure.use { oldStatePeek ->
                localEphemeralKeypair = oldStatePeek.localEphemeralKeypair
                // TODO: And if there isn't one yet, derive new keypair

                val resultingRatchetState = ratchetInternalWithNewEntropy(
                    oldState = oldStateSecure,
                    localEphemeralKeypair = localEphemeralKeypair,
                    incomingPublicKey = incomingEphemeralPublicKey,
                )

                newRatchetState = resultingRatchetState
            }
            require(newRatchetState != null) { "Null ratchet state" }
            newRatchetState
        } catch(e: Exception) {
            throw e     // TODO: Catch errors
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
            // TODO: Correct way to destroy a Secret Key Spec?
        }
    }

    /**
     * Secure wrapper for keypair maker
     */

    private fun generateEphemeralKeypair(): SecureKeyPair {
        return SecureKeyPair(MADH.generateKeypair())
    }

    // Begin info functions

    private fun getInfo(prefix: String, sessionNonce: ByteArray): ByteArray {
        require(sessionNonce.size == NUM_BYTES_IN_SESSION_NONCE) { "Session nonce was wrong size "}

        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)

        return ByteBuffer.allocate((prefixBytes.size + sessionNonce.size))
            .put(prefixBytes)
            .put(sessionNonce)
            .array()
    }

    private fun getInfoWithCounter(prefix: String, sessionNonce: ByteArray, counter: Int): ByteArray {
        require(sessionNonce.size == NUM_BYTES_IN_SESSION_NONCE) { "Session nonce was wrong size"}

        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        val counterBytes = numberToHexBytes(counter)
        val bufferSize = prefixBytes.size + sessionNonce.size + counterBytes.size

        return ByteBuffer.allocate(bufferSize)
            .put(prefixBytes)
            .put(sessionNonce)
            .put(counterBytes)
            .array()
    }

    private fun invalidateAllState(localLongtermKeypair: SecureKeyPair, remotePublicKey: Curve25519PublicKey) {
        localLongtermKeypair.close()
        remotePublicKey.bytes.fill(0)
    }

    val RADIX_FOR_COUNTER_ENCODING = 16

    private fun numberToHexBytes(number: Int): ByteArray {
        return number
            .toString(RADIX_FOR_COUNTER_ENCODING)
            .toByteArray(Charsets.UTF_8)
    }

    private fun decodeHexBytesToNumber(bytes: ByteArray): Int? {
        try {
            return bytes
                .toString(Charsets.UTF_8)
                .toInt(RADIX_FOR_COUNTER_ENCODING)
        }
        catch(e: Exception) {
            throw IllegalArgumentException("Could not decode into hex")
        }
    }

    const val ERROR_MESSAGE_NEW_HANDSHAKE_REQUIRED = "Ratchet error. New handshake required."


}

object KeyContext {
    object RootKey {
        const val SALT = "SHOUT-v1-Salt-RootKey"
        const val INFOPREFIX = "SHOUT-ROOT"
    }

    object ChainKey {
        const val INFOPREFIX = "SHOUT-CHAIN"
    }


}