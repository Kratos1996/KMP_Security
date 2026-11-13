package com.ishant.security.handshake

import kotlinx.serialization.Serializable

/** Public handshake fields only. The transport should Base64-encode byte arrays. */
@Serializable
data class ClientHello(
    val protocolVersion: Int = CURRENT_VERSION,
    val keyAgreement: String = "X25519",
    val keyDerivation: String = "HKDF-SHA256",
    val encryption: String = "AES-256-GCM",
    val clientEphemeralPublicKey: ByteArray,
    val clientNonce: ByteArray
) {
    companion object { const val CURRENT_VERSION = 1 }
}

@Serializable
data class ServerHello(
    val protocolVersion: Int = ClientHello.CURRENT_VERSION,
    val sessionId: String,
    val serverEphemeralPublicKey: ByteArray,
    val serverNonce: ByteArray,
    val signingKeyId: String,
    val signature: ByteArray
)

/**
 * Must verify the transcript using a pre-trusted/pinned backend signing key.
 * Never trust a key delivered only in the unauthenticated ServerHello.
 */
fun interface ServerHandshakeVerifier {
    suspend fun verify(signingKeyId: String, transcript: ByteArray, signature: ByteArray): Boolean
}
