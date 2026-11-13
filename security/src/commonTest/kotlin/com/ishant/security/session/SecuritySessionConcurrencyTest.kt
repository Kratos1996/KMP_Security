package com.ishant.security.session

import com.ishant.security.keys.RawAesKey
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SecuritySessionConcurrencyTest {

    @Test
    fun concurrentRequestsReceiveUniqueMonotonicSequences() = runTest {
        val session = newSession()
        try {
            val messages = coroutineScope {
                (0 until MESSAGE_COUNT).map { index ->
                    async { session.encryptRequest("request-$index".encodeToByteArray()) }
                }.awaitAll()
            }

            assertEquals(
                (0L until MESSAGE_COUNT.toLong()).toList(),
                messages.map { it.sequence }.sorted()
            )
            assertEquals(MESSAGE_COUNT, messages.map { it.sequence }.toSet().size)
        } finally {
            session.close()
        }
    }

    @Test
    fun concurrentDuplicateResponsesOnlyAllowOneSuccessfulDecryption() = runTest {
        val session = newSession()
        val aes = com.ishant.security.crypto.Aes256Gcm()
        try {
            val key = session.responseKey
            val plaintext = "server response".encodeToByteArray()
            val aad = "yralfood-security/v1|test-session|s2c|0".encodeToByteArray()
            val encrypted = aes.encrypt(plaintext, key, aad)
            val message = SequencedCiphertext(sequence = 0, payload = encrypted)

            val results = coroutineScope {
                List(2) { async { runCatching { session.decryptResponse(message) } } }.awaitAll()
            }

            assertEquals(1, results.count { it.isSuccess })
            assertEquals(1, results.count { it.isFailure })
            assertEquals("server response", results.single { it.isSuccess }.getOrThrow().decodeToString())
        } finally {
            session.close()
        }
    }

    @Test
    fun closedSessionRejectsNewOperations() = runTest {
        val session = newSession()
        session.close()

        assertFailsWith<com.ishant.security.core.SecurityError.SessionClosed> {
            session.encryptRequest(byteArrayOf(1))
        }
    }


    @Test
    fun closeZeroesBothKeysAndRejectsSubsequentCalls() = runTest {
        val session = newSession()
        session.close()

        assertEquals(0, session.requestKey.bytes.count { it != 0.toByte() })
        assertEquals(0, session.responseKey.bytes.count { it != 0.toByte() })
        assertFailsWith<com.ishant.security.core.SecurityError.SessionClosed> {
            session.encryptRequest(byteArrayOf(7))
        }
    }

    private fun newSession() = SecuritySession(
        sessionId = "test-session",
        requestKey = RawAesKey(ByteArray(32) { 1 }),
        responseKey = RawAesKey(ByteArray(32) { 2 })
    )

    private companion object {
        const val MESSAGE_COUNT = 64
    }
}
