package org.operatorfoundation.ratchet

import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PrivateKey
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.models.keys.ChainKey
import org.operatorfoundation.ratchet.models.keys.MessageKey
import org.operatorfoundation.ratchet.models.keys.RootKey
import org.operatorfoundation.ratchet.models.keys.SharedKey
import org.operatorfoundation.ratchet.models.PlaintextMessage
import org.operatorfoundation.ratchet.models.RatchetState
import org.operatorfoundation.ratchet.models.SingleUseRatchetState
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Main API for the Double Ratchet algorithm.
 *
 * The Double Ratchet provides forward secrecy and break-in recovery for
 * asynchronous messaging by combining a Diffie-Hellman ratchet with a
 * symmetric key ratchet.
 */
object Ratchet
{
    private const val HKDF_INFO = "SHOUT"
    private const val HMAC_ALGORITHM = "HmacSHA256"
    const val VALID_KEY_LENGTH = 32

    class RatchetSendResult(
        val state: RatchetState,
        val ephemeralPublicKeyToSend: Curve25519PublicKey
    )

    /**
     * Perform Elliptic Curve Diffie-Hellman key exchange using BouncyCastle
     */
    private fun ecdh(privateKey: Curve25519PrivateKey, publicKey: Curve25519PublicKey): ByteArray
    {
        // BouncyCastle X25519 key agreement
        val privateKeyBytes = privateKey.bytes
        val publicKeyBytes = publicKey.bytes

        // Ensure we have the correct key sizes
        require(privateKeyBytes.size == VALID_KEY_LENGTH) { "Private key must be $VALID_KEY_LENGTH bytes" }
        require(publicKeyBytes.size == VALID_KEY_LENGTH) { "Public key must be $VALID_KEY_LENGTH bytes" }

        // Perform X25519 scalar multiplication: shared_secret = privateKey * publicKey
        val sharedSecret = ByteArray(VALID_KEY_LENGTH)
        org.bouncycastle.math.ec.rfc7748.X25519.scalarMult(
            privateKeyBytes,
            0,
            publicKeyBytes,
            0,
            sharedSecret,
            0
        )

        return sharedSecret
    }

    /**
     * HKDF (HMAC-based Key Derivation Function) implementation
     * Returns 64 bytes (32 for root key, 32 for chain key)
     */
    private fun hkdf(oldRootKey: ByteArray, sharedKey: ByteArray, info: String): ByteArray
    {
        // HKDF-Extract: PRK = HMAC(salt=oldRootKey, ikm=sharedKey)
        val prk = hmac(oldRootKey, sharedKey)

        // HKDF-Expand: Generate 64 bytes (32 for new root key, 32 for chain key)
        val infoBytes = info.toByteArray()
        val t1 = hmac(prk, infoBytes + byteArrayOf(0x01))
        val t2 = hmac(prk, t1 + infoBytes + byteArrayOf(0x02))

        // Concatenate to return full 64 bytes
        return t1 + t2
    }

    /**
     * HMAC-SHA256 function
     */
    private fun hmac(key: ByteArray, data: ByteArray): ByteArray
    {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKey = SecretKeySpec(key, HMAC_ALGORITHM)
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    /**
     * Creates a new ratchet state from long-term keys.
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
        localLongtermKeypair: Curve25519KeyPair,
        remoteLongtermPublicKey: Curve25519PublicKey
    ): SingleUseRatchetState
    {
        // Derive initial root key from long-term keys: R_0 = ECDH(priv_a0, k_b0)
        val sharedSecret = ecdh(localLongtermKeypair.privateKey, remoteLongtermPublicKey)
        val initialRootKey = RootKey.fromECDH(sharedSecret)

        // Return initial state with defaults for optional fields
        val newRatchetState = RatchetState(
            localLongtermKeypair = localLongtermKeypair,
            remoteLongtermPublicKey = remoteLongtermPublicKey,
            rootKey = initialRootKey
        )

        return SingleUseRatchetState(newRatchetState)
    }

    /**
     * Advances the ratchet with new ephemeral keys (DH ratchet step).
     * This should be called when receiving a message with a new public key.
     *
     * @param oldState The current ratchet state
     * @param remotePublicKey New remote ephemeral public key
     * @return The updated ratchet state
     */
    private fun ratchetInternal(
        oldState: RatchetState,
        localKeypair: Curve25519KeyPair,
        remotePublicKey: Curve25519PublicKey
    ): RatchetState
    {
        // Perform ECDH with new keys: S_r = ECDH(priv_r, k_r)
        val sharedSecret = ecdh(localKeypair.privateKey, remotePublicKey)
        val sharedKey = SharedKey.fromECDH(sharedSecret)

        // Derive new root and chain keys: (R_n, C_n) = HKDF(R_{n-1}, S_n, "SHOUT")
        val hkdfOutput = hkdf(oldState.rootKey.bytes, sharedSecret, HKDF_INFO)
        val newRootKey = RootKey.fromHKDF(hkdfOutput)
        val chainKey = ChainKey.fromHKDF(hkdfOutput)

        // Increment message number and derive message key: M_n = HMAC(C_n, n)
        val newMessageNumber = oldState.messageNumber + 1
        val hmacOutput = hmac(chainKey.bytes, newMessageNumber.toString().toByteArray())
        val messageKey = MessageKey.fromHMAC(hmacOutput)

        return RatchetState(
            localLongtermKeypair = oldState.localLongtermKeypair,
            remoteLongtermPublicKey = oldState.remoteLongtermPublicKey,
            rootKey = newRootKey,
            messageNumber = newMessageNumber,
            chainKey = chainKey,
            sharedKey = sharedKey,
            messageKey = messageKey,
            localEphemeralKeypair = localKeypair,
            remoteEphemeralPublicKey = remotePublicKey
        )
    }

    /**
     * Ratchet for sending a message.
     * Generates a new ephemeral keypair and uses the current remote public key.
     *
     * @param oldState The current ratchet state
     * @return Result containing the new state and the ephemeral public key to send
     */
    fun ratchetForSend(oldState: RatchetState): RatchetSendResult
    {
        val newKeypair = MADH.generateKeypair()
        val remoteKey = oldState.remoteEphemeralPublicKey ?: oldState.remoteLongtermPublicKey
        val newState = ratchetInternal(oldState, newKeypair, remoteKey)

        return RatchetSendResult(newState, newKeypair.publicKey)
    }

    /**
     * Ratchet for receiving a message.
     * Uses the current local keypair with the sender's new ephemeral public key.
     *
     * @param oldState The current ratchet state
     * @param senderEphemeralPublicKey The ephemeral public key received from the sender
     * @return The updated ratchet state
     */
    fun ratchetForReceive(oldState: RatchetState, senderEphemeralPublicKey: Curve25519PublicKey): RatchetState
    {
        val localKeypair = oldState.localEphemeralKeypair ?: oldState.localLongtermKeypair
        return ratchetInternal(oldState, localKeypair, senderEphemeralPublicKey)
    }

    /**
     * Advances the ratchet without new keys (symmetric ratchet step).
     * This should be called when sending/receiving multiple messages
     * without a key change (consecutive messages, same sender).
     *
     * @param oldState The current ratchet state
     * @return The updated ratchet state with new chain and message keys
     */
    fun symmetricRatchet(oldState: RatchetState): RatchetState
    {
        // Ensure we have a chain key to work with
        requireNotNull(oldState.chainKey) { "Cannot ratchet without a chain key. Call ratchetWithNewKey first." }

        // Increment message number
        val newMessageNumber = oldState.messageNumber + 1

        // Derive new chain key: C_n = HMAC(C_{n-1}, n)
        val chainHmacOutput = hmac(oldState.chainKey.bytes, newMessageNumber.toString().toByteArray())
        val newChainKey = ChainKey.fromHMAC(chainHmacOutput)

        // Derive new message key: M_n = HMAC(C_n, n)
        val messageHmacOutput = hmac(newChainKey.bytes, newMessageNumber.toString().toByteArray())
        val newMessageKey = MessageKey.fromHMAC(messageHmacOutput)

        return oldState.copy(
            messageNumber = newMessageNumber,
            chainKey = newChainKey,
            messageKey = newMessageKey
        )
    }

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
}