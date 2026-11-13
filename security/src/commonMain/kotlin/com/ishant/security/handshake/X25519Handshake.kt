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
        if (serverHello.protocolVersion != ClientHello.CURRENT_VERSION) {
            throw SecurityError.InvalidHandshake("Unsupported protocol version")
        }
        if (serverHello.sessionId.isBlank() || serverHello.sessionId.length > 128) {
            throw SecurityError.InvalidHandshake("Invalid session id")
        }
        if (serverHello.serverNonce.size != NONCE_SIZE || serverHello.signature.isEmpty() ||
            serverHello.signingKeyId.isBlank() || serverHello.serverEphemeralPublicKey.isEmpty()
        ) throw SecurityError.InvalidHandshake("Incomplete server hello")

        val transcript = HandshakeTranscript.encode(pending.clientHello, serverHello)
        if (!verifier.verify(serverHello.signingKeyId, transcript, serverHello.signature)) {
            throw SecurityError.HandshakeAuthenticationFailed
        }

        return try {
            val serverPublic = xdh.publicKeyDecoder(XDH.Curve.X25519)
                .decodeFromByteArray(XDH.PublicKey.Format.DER, serverHello.serverEphemeralPublicKey)
            val sharedSecret = pending.privateKey.sharedSecretGenerator()
                .generateSharedSecretToByteArray(serverPublic)
            val salt = pending.clientHello.clientNonce + serverHello.serverNonce
            val hkdf = provider.get(HKDF)

            fun derive(direction: String): RawAesKey {
                val info = ("yralfood-security/v1/${serverHello.sessionId}/$direction").encodeToByteArray()
                val keyBytes = hkdf.secretDerivation(
                    digest = SHA256,
                    outputSize = 256.bits,
                    salt = salt,
                    info = info
                ).deriveSecretToByteArray(sharedSecret)
                return RawAesKey(keyBytes)
            }

            SecuritySession(
                sessionId = serverHello.sessionId,
                requestKey = derive("client-to-server"),
                responseKey = derive("server-to-client")
            )
        } catch (error: SecurityError) {
            throw error
        } catch (cause: Throwable) {
            throw SecurityError.KeyAgreementFailed(cause)
        }
    }

    private companion object { const val NONCE_SIZE = 32 }
}

class PendingClientHandshake internal constructor(
    val clientHello: ClientHello,
    internal val privateKey: XDH.PrivateKey
)
