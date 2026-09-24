package org.operatorfoundation.ratchet

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
import org.operatorfoundation.ratchet.models.keys.restriction.SecureKeypair
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
 * TODO: Zeroize and test
 *
 */

object Ratchet
{
    private const val HKDF_INFO = "SHOUT"
    const val VALID_NUM_BYTES_IN_KEY = 32

    class RatchetSendResult(
        val state: SecureRatchetState,
        val ephemeralPublicKeyToSend: Curve25519PublicKey
    )


    // ========== Creating a new ratchet state ==========

    /**
     * Creates a new ratchet state from long-term keys (JG: or ephemeral keys, right? if so change the param names)
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
        remoteLongtermPublicKey: Curve25519PublicKey
    ): SecureRatchetState
    {
        var newRatchetState: SecureRatchetState? = null

        localLongtermKeypair.use { keypair ->

            val localLongtermPrivateKey = keypair.privateKey

            // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
            val sharedSecret = ecdh(localLongtermPrivateKey, remoteLongtermPublicKey)
            val initialRootKey = RootKey.fromECDH(sharedSecret)

            // Return initial state with defaults for optional fields
            val newState = RatchetState(
                localLongtermKeypair = keypair,
                remoteLongtermPublicKey = remoteLongtermPublicKey,
                rootKey = initialRootKey
            )

            newRatchetState = SecureRatchetState(newState)
        }

        return newRatchetState!!
    }

    // ========== Advancing the ratchet, with or without new ephemeral keys ==========


    /**
     * Advances the ratchet _with_ new ephemeral keys (DH ratchet step).
     * This should be called when receiving a message with a new public key.
     *
     * Formerly "ratchetWithNewKey()"
     *
     *
     * @param oldState The current ratchet state
     * @param remotePublicKey New remote ephemeral public key
     * @return The updated ratchet state
     */
    fun ratchetInternalWithIncomingKey(
        oldState: SecureRatchetState,
        localKeypair: SecureKeypair,
        remotePublicKey: Curve25519PublicKey
    ): SecureRatchetState
    {
        var nextRatchetState: SecureRatchetState? = null

        localKeypair.use { localKeypair ->

            oldState.use { oldState ->

                // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
                val sharedSecret = ecdh(localKeypair.privateKey, remotePublicKey)
                val sharedKey = SharedKey.fromECDH(sharedSecret)

                // Derive new root and chain keys: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
                val hkdfOutput = performHKDF(oldState.rootKey.bytes, sharedSecret, HKDF_INFO)
                val newRootKey = RootKey.fromHKDF(hkdfOutput)
                val newChainKey = ChainKey.fromHKDF(hkdfOutput)

                // Increment message number and derive message key: M_n = HMAC(C_n, n)
                val newMessageNumber = oldState.messageNumber + 1
                val hmacOutput =
                    performHMAC(newChainKey.bytes, newMessageNumber.toString().toByteArray())
                val messageKey = MessageKey.fromHMAC(hmacOutput)

                val newState = RatchetState(
                    localLongtermKeypair = oldState.localLongtermKeypair,
                    remoteLongtermPublicKey = oldState.remoteLongtermPublicKey,
                    rootKey = newRootKey,
                    messageNumber = newMessageNumber,
                    chainKey = newChainKey,
                    sharedKey = sharedKey,
                    messageKey = messageKey,
                    localEphemeralKeypair = localKeypair,
                    remoteEphemeralPublicKey = remotePublicKey
                )

                nextRatchetState = SecureRatchetState(newState)
            }
        }

        return nextRatchetState ?: throw Exception("Null ratchet state")
    }


    /**
     * Advances the ratchet without new keys (symmetric ratchet step).
     * This should be called when sending/receiving multiple messages
     * without a key change (consecutive messages, same sender).
     *
     * Formerly "ratchetWithoutNewKey()"
     *
     * @param oldState The current ratchet state
     * @return The updated ratchet state with new chain and message keys
     */
    fun symmetricRatchetWithoutIncomingKey(oldState: SecureRatchetState): SecureRatchetState
    {
        var nextRatchetState: SecureRatchetState? = null

        oldState.use { oldState ->

            // Ensure we have a chain key to work with
            requireNotNull(oldState.chainKey) { "Cannot ratchet without a chain key. Call ratchetWithNewKey first." }

            // Increment message number
            val newMessageNumber = oldState.messageNumber + 1

            // Derive new chain key: C_n = HMAC(C_{n-1}, n)
            val chainHmacOutput =
                performHMAC(oldState.chainKey.bytes, newMessageNumber.toString().toByteArray())
            val newChainKey = ChainKey.fromHMAC(chainHmacOutput)

            // Derive new message key: M_n = HMAC(C_n, n)
            val messageHmacOutput =
                performHMAC(newChainKey.bytes, newMessageNumber.toString().toByteArray())
            val newMessageKey = MessageKey.fromHMAC(messageHmacOutput)

            val newState = oldState.deepCopy(
                messageNumber = newMessageNumber,
                chainKey = newChainKey,
                messageKey = newMessageKey
            )

            // TODO: Zeroize everything else

            nextRatchetState = SecureRatchetState(newState)
        }

        return nextRatchetState ?: throw Exception("Null ratchet state")
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

        oldState.use { oldState ->
            val newSecureKeypair = generateMADHKeypair()
            newSecureKeypair.use { newKeypair ->
                val remoteKey = oldState.remoteEphemeralPublicKey ?: oldState.remoteLongtermPublicKey
                ratchetInternalWithIncomingKey(SecureRatchetState(oldState), newSecureKeypair, remoteKey).use { newState ->
                    val singleUseNewState = SecureRatchetState(newState)
                    result = RatchetSendResult(singleUseNewState, newKeypair.publicKey)
                }
            }
        }
        return result ?: throw Exception("Null ratchet send result")
    }

    /**
     * Ratchet for receiving a message.
     * Uses the current local keypair with the sender's new ephemeral public key.
     *
     * @param oldState The current ratchet state
     * @param senderEphemeralPublicKey The ephemeral public key received from the sender
     * @return The updated ratchet state
     */
    fun ratchetForReceive(oldStateSecure: SecureRatchetState, senderEphemeralPublicKey: Curve25519PublicKey): SecureRatchetState
    {
        var result: SecureRatchetState? = null

        oldStateSecure.use { oldState ->
            // TODO: As we work on this remediation item see if we should encapsulate
            val localKeypair = oldState.localEphemeralKeypair ?: oldState.localLongtermKeypair
            ratchetInternalWithIncomingKey(oldStateSecure, SecureKeypair(localKeypair), senderEphemeralPublicKey).use { newState ->
                result = SecureRatchetState(newState)
            }
        }
        return result ?: throw Exception("Null ratchet state")
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
        // Serialize the plaintext message to bytes
        val plaintextBytes = plaintext.toBytes()

        // Create AES-GCM key from the message key
        val aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes)

        // Create cipher and encrypt
        val cipher = org.operatorfoundation.aes.AesCipher()
        return cipher.encrypt(aesKey, plaintextBytes)
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
        try {

            // Create AES-GCM key from the message key
            val aesKey = org.operatorfoundation.aes.AesGcmKey(key.bytes)

            // Create cipher and decrypt
            val cipher = org.operatorfoundation.aes.AesCipher()
            val decryptedBytes = cipher.decrypt(aesKey, ciphertext)

            // Deserialize the plaintext message
            return PlaintextMessage.fromBytes(decryptedBytes)
        }
        catch(e: IllegalArgumentException) {
            return null
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
        require(privateKeyBytes.size == VALID_NUM_BYTES_IN_KEY) { "Private key must be $VALID_NUM_BYTES_IN_KEY bytes" }
        require(publicKeyBytes.size == VALID_NUM_BYTES_IN_KEY) { "Public key must be $VALID_NUM_BYTES_IN_KEY bytes" }

        // Perform X25519 scalar multiplication: shared_secret = privateKey * publicKey
        val sharedSecret = ByteArray(VALID_NUM_BYTES_IN_KEY)
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
    private fun performHKDF(oldRootKey: ByteArray, sharedSecret: Secret, info: String): ByteArray
    {
        var result: ByteArray? = null

        sharedSecret.use { sharedKey ->
            // HKDF-Extract: PRK = HMAC(salt=oldRootKey, ikm=sharedKey)
            val prk = performHMAC(oldRootKey, sharedKey)

            // HKDF-Expand: Generate 64 bytes (32 for new root key, 32 for chain key)
            val infoBytes = info.toByteArray()
            val t1 = performHMAC(prk, infoBytes + byteArrayOf(0x01))
            val t2 = performHMAC(prk, t1 + infoBytes + byteArrayOf(0x02))
            result = t1 + t2

        }
        // Concatenate to return full 64 bytes
        return result!!
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
     *
     *
     */

    // TODO: Secure? Check if the sibling library makes a copy, or what.

    fun generateMADHKeypair(): SecureKeypair {
        return SecureKeypair(MADH.generateKeypair())
    }
}