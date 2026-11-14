package com.ishant.security.handshake

import com.ishant.security.crypto.Aes256Gcm
import com.ishant.security.core.SecurityError
import com.ishant.security.session.SequencedCiphertext
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.XDH
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class X25519HandshakeTest {
    @Test
    fun clientAndServerDeriveMatchingDirectionalKeysAndProtectMessages() = runTest {
        val provider = CryptographyProvider.Default
        val xdh = provider.get(XDH)
        val serverPair = xdh.keyPairGenerator(XDH.Curve.X25519).generateKey()
        val serverNonce = CryptographyRandom.nextBytes(32)
        val handshake = X25519Handshake()
        val pending = handshake.begin()
        val sessionId = "test-session-001"
        val serverHello = ServerHello(
            sessionId = sessionId,
            serverEphemeralPublicKey = serverPair.publicKey.encodeToByteArray(XDH.PublicKey.Format.DER),
            serverNonce = serverNonce,
            signingKeyId = "test-key",
            signature = byteArrayOf(1, 2, 3)
        )
        var verifiedTranscript: ByteArray? = null
        val session = handshake.complete(pending, serverHello, ServerHandshakeVerifier { keyId, transcript, signature ->
            assertEquals("test-key", keyId)
            assertContentEquals(byteArrayOf(1, 2, 3), signature)
            verifiedTranscript = transcript
            true
        })
        assertTrue(verifiedTranscript?.isNotEmpty() == true)

        val clientPublic = xdh.publicKeyDecoder(XDH.Curve.X25519)
            .decodeFromByteArray(XDH.PublicKey.Format.DER, pending.clientHello.clientEphemeralPublicKey)
        val serverShared = serverPair.privateKey.sharedSecretGenerator()
            .generateSharedSecretToByteArray(clientPublic)
        val salt = pending.clientHello.clientNonce + serverNonce
        val hkdf = provider.get(HKDF)
        suspend fun serverKey(label: String): ByteArray = hkdf.secretDerivation(
            digest = SHA256,
            outputSize = 256.bits,
            salt = salt,
            info = "kmp-security/v1/$sessionId/$label".encodeToByteArray()
        ).deriveSecretToByteArray(serverShared)

        val request = session.encryptRequest("hello backend".encodeToByteArray())
        assertEquals(0L, request.sequence)
        val serverAes = Aes256Gcm()
        val requestClear = serverAes.decrypt(
            request.payload,
            com.ishant.security.keys.RawAesKey(serverKey("client-to-server")),
            "kmp-security/v1|$sessionId|c2s|0".encodeToByteArray()
        )
        assertEquals("hello backend", requestClear.decodeToString())

        val responsePayload = serverAes.encrypt(
            "hello app".encodeToByteArray(),
            com.ishant.security.keys.RawAesKey(serverKey("server-to-client")),
            "kmp-security/v1|$sessionId|s2c|0".encodeToByteArray()
        )
        val response = SequencedCiphertext(0L, responsePayload)
        assertEquals("hello app", session.decryptResponse(response).decodeToString())
        assertFailsWith<SecurityError.ReplayOrOutOfOrderMessage> {
            session.decryptResponse(response)
        }
    }

    @Test
    fun invalidServerSignatureIsRejected() = runTest {
        val provider = CryptographyProvider.Default
        val serverPair = provider.get(XDH).keyPairGenerator(XDH.Curve.X25519).generateKey()
        val pending = X25519Handshake().begin()
        val hello = ServerHello(
            sessionId = "test-session",
            serverEphemeralPublicKey = serverPair.publicKey.encodeToByteArray(XDH.PublicKey.Format.DER),
            serverNonce = CryptographyRandom.nextBytes(32),
            signingKeyId = "untrusted",
            signature = byteArrayOf(9)
        )
        assertFailsWith<SecurityError.HandshakeAuthenticationFailed> {
            X25519Handshake().complete(pending, hello, ServerHandshakeVerifier { _, _, _ -> false })
        }
    }
    @Test
    fun unsupportedClientSuiteIsRejectedBeforeSignatureVerification() = runTest {
        val pending = X25519Handshake().begin()
        val altered = pending.clientHello.copy(encryption = "AES-128-GCM")
        val mutatedPending = PendingClientHandshake(
            altered,
            CryptographyProvider.Default.get(XDH)
                .keyPairGenerator(XDH.Curve.X25519).generateKey().privateKey
        )
        val hello = ServerHello(
            sessionId = "test-session",
            serverEphemeralPublicKey = byteArrayOf(1),
            serverNonce = ByteArray(32),
            signingKeyId = "test-key",
            signature = byteArrayOf(1)
        )
        assertFailsWith<SecurityError.InvalidHandshake> {
            X25519Handshake().complete(mutatedPending, hello, ServerHandshakeVerifier { _, _, _ ->
                error("Verifier must not be called for unsupported suite")
            })
        }
    }

    @Test
    fun malformedServerPublicKeyAndNonceAreRejected() = runTest {
        val pending = X25519Handshake().begin()
        val hello = ServerHello(
            sessionId = "test-session",
            serverEphemeralPublicKey = ByteArray(257),
            serverNonce = ByteArray(31),
            signingKeyId = "test-key",
            signature = byteArrayOf(1)
        )
        assertFailsWith<SecurityError.InvalidHandshake> {
            X25519Handshake().complete(pending, hello, ServerHandshakeVerifier { _, _, _ ->
                error("Verifier must not be called for malformed server hello")
            })
        }
    }

}
