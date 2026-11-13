package com.ishant.security.handshake

import com.ishant.security.core.SecurityError
import com.ishant.security.keys.RawAesKey
import com.ishant.security.session.SecuritySession
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.XDH
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlin.coroutines.cancellation.CancellationException

/** Client-side ephemeral X25519 handshake. Private key bytes are never exported. */
class X25519Handshake {
    private val provider = CryptographyProvider.Default
    private val xdh = provider.get(XDH)

    suspend fun begin(): PendingClientHandshake {
        val pair = xdh.keyPairGenerator(XDH.Curve.X25519).generateKey()
        val hello = ClientHello(
            clientEphemeralPublicKey = pair.publicKey.encodeToByteArray(XDH.PublicKey.Format.DER),
            clientNonce = CryptographyRandom.nextBytes(NONCE_SIZE)
        )
        return PendingClientHandshake(hello, pair.privateKey)
    }

    suspend fun complete(
        pending: PendingClientHandshake,
        serverHello: ServerHello,
        verifier: ServerHandshakeVerifier
    ): SecuritySession {
        // Validate both sides before consuming the one-time ephemeral private key.
        // The transcript binds these values, but unsupported suites must never be accepted.
        val clientHello = pending.clientHello
        if (clientHello.protocolVersion != ClientHello.CURRENT_VERSION ||
            clientHello.keyAgreement != "X25519" ||
            clientHello.keyDerivation != "HKDF-SHA256" ||
            clientHello.encryption != "AES-256-GCM" ||
            clientHello.clientNonce.size != NONCE_SIZE ||
            clientHello.clientEphemeralPublicKey.size !in 1..MAX_PUBLIC_KEY_BYTES
        ) throw SecurityError.InvalidHandshake("Unsupported or malformed client hello")

        if (serverHello.protocolVersion != ClientHello.CURRENT_VERSION) {
            throw SecurityError.InvalidHandshake("Unsupported protocol version")
        }
        if (serverHello.sessionId.isBlank() || serverHello.sessionId.length > 128) {
            throw SecurityError.InvalidHandshake("Invalid session id")
        }
        if (serverHello.serverNonce.size != NONCE_SIZE || serverHello.signature.isEmpty() ||
            serverHello.signatureAlgorithm != "Ed25519" ||
            serverHello.signingKeyId.isBlank() || serverHello.signingKeyId.length > 128 ||
            !isX25519SubjectPublicKeyInfo(serverHello.serverEphemeralPublicKey)
        ) throw SecurityError.InvalidHandshake("Incomplete server hello")

        val privateKey = pending.consumePrivateKey()
        val transcript = HandshakeTranscript.encode(pending.clientHello, serverHello)
        if (!verifier.verify(serverHello.signingKeyId, transcript, serverHello.signature)) {
            throw SecurityError.HandshakeAuthenticationFailed
        }

        return try {
            val serverPublic = xdh.publicKeyDecoder(XDH.Curve.X25519)
                .decodeFromByteArray(XDH.PublicKey.Format.DER, serverHello.serverEphemeralPublicKey)
            val sharedSecret = privateKey.sharedSecretGenerator()
                .generateSharedSecretToByteArray(serverPublic)
            try {
                val salt = pending.clientHello.clientNonce + serverHello.serverNonce
                val hkdf = provider.get(HKDF)

                suspend fun derive(direction: String): RawAesKey {
                    val info = ("yralfood-security/v1/${serverHello.sessionId}/$direction").encodeToByteArray()
                    val keyBytes = hkdf.secretDerivation(
                        digest = SHA256,
                        outputSize = 256.bits,
                        salt = salt,
                        info = info
                    ).deriveSecretToByteArray(sharedSecret)
                    return try { RawAesKey(keyBytes) } finally { keyBytes.fill(0) }
                }

                SecuritySession(
                    sessionId = serverHello.sessionId,
                    requestKey = derive("client-to-server"),
                    responseKey = derive("server-to-client")
                )
            } finally {
                sharedSecret.fill(0)
            }
        } catch (error: SecurityError) {
            throw error
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (cause: Throwable) {
            throw SecurityError.KeyAgreementFailed(cause)
        }
    }

    private fun isX25519SubjectPublicKeyInfo(encoded: ByteArray): Boolean =
        encoded.size == X25519_SPKI_PREFIX.size + X25519_PUBLIC_KEY_SIZE &&
            encoded.copyOfRange(0, X25519_SPKI_PREFIX.size).contentEquals(X25519_SPKI_PREFIX)

    private companion object {
        const val NONCE_SIZE = 32
        const val X25519_PUBLIC_KEY_SIZE = 32
        val X25519_SPKI_PREFIX = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03,
            0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00
        )
    }
}

class PendingClientHandshake internal constructor(
    val clientHello: ClientHello,
    privateKey: XDH.PrivateKey
) {
    private var privateKey: XDH.PrivateKey? = privateKey

    internal fun consumePrivateKey(): XDH.PrivateKey =
        privateKey?.also { privateKey = null }
            ?: throw SecurityError.InvalidHandshake("Client handshake has already been consumed")
}
