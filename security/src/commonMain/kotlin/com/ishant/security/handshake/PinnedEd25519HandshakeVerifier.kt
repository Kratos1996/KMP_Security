package com.ishant.security.handshake

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EdDSA

/**
 * Verifies ServerHello signatures using an allow-listed set of Ed25519 public
 * keys provisioned by the application. Keys are DER-encoded SubjectPublicKeyInfo.
 *
 * Key rotation must be performed by an authenticated app release/configuration
 * channel; a key received only in ServerHello is never trusted.
 */
class PinnedEd25519HandshakeVerifier(
    trustedPublicKeys: Map<String, ByteArray>,
    private val provider: CryptographyProvider = CryptographyProvider.Default
) : ServerHandshakeVerifier {

    private val pinnedKeys: Map<String, ByteArray> = trustedPublicKeys.mapValues { (keyId, encoded) ->
        require(keyId.isNotBlank() && keyId.length <= MAX_KEY_ID_LENGTH) {
            "Invalid pinned signing key id"
        }
        require(encoded.isNotEmpty() && encoded.size <= MAX_PUBLIC_KEY_DER_SIZE) {
            "Invalid Ed25519 public key encoding"
        }
        encoded.copyOf()
    }

    init {
        require(pinnedKeys.isNotEmpty()) { "At least one trusted Ed25519 key is required" }
    }

    override suspend fun verify(
        signingKeyId: String,
        transcript: ByteArray,
        signature: ByteArray
    ): Boolean {
        if (signingKeyId.isBlank() || transcript.isEmpty() || signature.size != ED25519_SIGNATURE_SIZE) {
            return false
        }

        val encodedKey = pinnedKeys[signingKeyId] ?: return false
        return try {
            val edDsa = provider.get(EdDSA)
            val publicKey = edDsa.publicKeyDecoder(EdDSA.Curve.Ed25519)
                .decodeFromByteArray(EdDSA.PublicKey.Format.DER, encodedKey)
            publicKey.signatureVerifier().tryVerifySignature(transcript, signature)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            false
        }
    }

    private companion object {
        const val MAX_KEY_ID_LENGTH = 128
        const val MAX_PUBLIC_KEY_DER_SIZE = 1024
        const val ED25519_SIGNATURE_SIZE = 64
    }
}
