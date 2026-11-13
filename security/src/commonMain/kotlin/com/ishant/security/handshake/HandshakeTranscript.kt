package com.ishant.security.handshake

/** Canonical length-prefixed transcript. The signature excludes its own signature bytes. */
internal object HandshakeTranscript {
    fun encode(client: ClientHello, server: ServerHello): ByteArray {
        val fields = listOf(
            "yralfood-security-handshake-v1".encodeToByteArray(),
            client.protocolVersion.toString().encodeToByteArray(),
            client.keyAgreement.encodeToByteArray(),
            client.keyDerivation.encodeToByteArray(),
            client.encryption.encodeToByteArray(),
            client.clientEphemeralPublicKey,
            client.clientNonce,
            server.protocolVersion.toString().encodeToByteArray(),
            server.sessionId.encodeToByteArray(),
            server.serverEphemeralPublicKey,
            server.serverNonce,
            server.signingKeyId.encodeToByteArray(),
            server.signatureAlgorithm.encodeToByteArray()
        )
        val out = ArrayList<Byte>()
        fields.forEach { field ->
            val n = field.size
            out.add((n ushr 24).toByte()); out.add((n ushr 16).toByte())
            out.add((n ushr 8).toByte()); out.add(n.toByte())
            field.forEach(out::add)
        }
        return out.toByteArray()
    }
}
