package com.ishant.security.session

import com.ishant.security.core.EncryptedPayload
import com.ishant.security.core.SecurityError
import com.ishant.security.crypto.Aes256Gcm
import com.ishant.security.keys.RawAesKey
import kotlinx.serialization.Serializable

/**
 * Direction-separated keys, session-bound AAD and strict in-order response checks.
 * Serialize calls to an instance: this class is intentionally not thread-safe.
 */
class SecuritySession internal constructor(
    val sessionId: String,
    internal val requestKey: RawAesKey,
    internal val responseKey: RawAesKey,
    private val aes: Aes256Gcm = Aes256Gcm()
) {
    private var nextRequestSequence = 0L
    private var nextResponseSequence = 0L
    private var closed = false

    suspend fun encryptRequest(plaintext: ByteArray): SequencedCiphertext {
        ensureOpen()
        if (nextRequestSequence == Long.MAX_VALUE) throw SecurityError.SequenceExhausted
        val sequence = nextRequestSequence
        val payload = aes.encrypt(plaintext, requestKey, aad("c2s", sequence))
        nextRequestSequence++
        return SequencedCiphertext(sequence, payload)
    }

    suspend fun decryptResponse(message: SequencedCiphertext): ByteArray {
        ensureOpen()
        if (message.sequence != nextResponseSequence) {
            throw SecurityError.ReplayOrOutOfOrderMessage(nextResponseSequence, message.sequence)
        }
        if (nextResponseSequence == Long.MAX_VALUE) throw SecurityError.SequenceExhausted
        val plaintext = aes.decrypt(message.payload, responseKey, aad("s2c", message.sequence))
        nextResponseSequence++
        return plaintext
    }

    fun close() {
        if (!closed) {
            closed = true
            requestKey.clear()
            responseKey.clear()
        }
    }

    private fun ensureOpen() {
        if (closed) throw SecurityError.SessionClosed
    }

    private fun aad(direction: String, sequence: Long): ByteArray =
        "yralfood-security/v1|$sessionId|$direction|$sequence".encodeToByteArray()
}

@Serializable
data class SequencedCiphertext(val sequence: Long, val payload: EncryptedPayload)
