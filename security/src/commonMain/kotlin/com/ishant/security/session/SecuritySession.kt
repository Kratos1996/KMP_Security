package com.ishant.security.session

import com.ishant.security.core.EncryptedPayload
import com.ishant.security.core.SecurityError
import com.ishant.security.crypto.Aes256Gcm
import com.ishant.security.keys.RawAesKey
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlin.coroutines.cancellation.CancellationException

/**
 * Direction-separated keys, session-bound AAD and strict in-order response checks.
 *
 * Request and response operations are serialized independently. This guarantees
 * unique, ordered sequence assignment for concurrent callers in each direction.
 * [close] is suspending and waits for both directions to become idle before
 * zeroing key material.
 */
class SecuritySession internal constructor(
    val sessionId: String,
    internal val requestKey: RawAesKey,
    internal val responseKey: RawAesKey,
    private val aes: Aes256Gcm = Aes256Gcm()
) {
    private val requestMutex = Mutex()
    private val responseMutex = Mutex()

    private var nextRequestSequence = 0L
    private var nextResponseSequence = 0L
    private var closed = false

    @Throws(SecurityError::class, CancellationException::class)
    suspend fun encryptRequest(plaintext: ByteArray): SequencedCiphertext =
        requestMutex.withLock {
            ensureOpen()
            if (nextRequestSequence == Long.MAX_VALUE) throw SecurityError.SequenceExhausted

            // Consume the sequence before invoking the provider. A failed/cancelled
            // encryption must never make the same protocol sequence reusable.
            val sequence = nextRequestSequence++
            val payload = aes.encrypt(plaintext, requestKey, aad("c2s", sequence))
            SequencedCiphertext(sequence, payload)
        }

    @Throws(SecurityError::class, CancellationException::class)
    suspend fun decryptResponse(message: SequencedCiphertext): ByteArray =
        responseMutex.withLock {
            ensureOpen()
            if (message.sequence != nextResponseSequence) {
                throw SecurityError.ReplayOrOutOfOrderMessage(nextResponseSequence, message.sequence)
            }
            if (nextResponseSequence == Long.MAX_VALUE) throw SecurityError.SequenceExhausted

            // Advance only after authentication succeeds, allowing a valid retry
            // after malformed/tampered input while still rejecting concurrent replay.
            val plaintext = aes.decrypt(message.payload, responseKey, aad("s2c", message.sequence))
            nextResponseSequence++
            plaintext
        }

    suspend fun close() {
        requestMutex.withLock {
            responseMutex.withLock {
                if (!closed) {
                    closed = true
                    requestKey.clear()
                    responseKey.clear()
                }
            }
        }
    }

    private fun ensureOpen() {
        if (closed) throw SecurityError.SessionClosed
    }

    private fun aad(direction: String, sequence: Long): ByteArray =
        "kmp-security/v1|$sessionId|$direction|$sequence".encodeToByteArray()
}

@Serializable
data class SequencedCiphertext(val sequence: Long, val payload: EncryptedPayload)
