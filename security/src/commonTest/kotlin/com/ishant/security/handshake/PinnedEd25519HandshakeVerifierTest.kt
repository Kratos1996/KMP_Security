package com.ishant.security.handshake

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EdDSA
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PinnedEd25519HandshakeVerifierTest {

    @Test
    fun acceptsSignatureFromPinnedKey() = runTest {
        val provider = CryptographyProvider.Default
        val eddsa = provider.get(EdDSA)
        val pair = eddsa.keyPairGenerator(EdDSA.Curve.Ed25519).generateKey()
        val publicKey = pair.publicKey.encodeToByteArray(EdDSA.PublicKey.Format.DER)
        val transcript = "canonical handshake transcript".encodeToByteArray()
        val signature = pair.privateKey.signatureGenerator().generateSignature(transcript)

        val verifier = PinnedEd25519HandshakeVerifier(
            trustedPublicKeys = mapOf("backend-key-v1" to publicKey),
            provider = provider
        )

        assertTrue(verifier.verify("backend-key-v1", transcript, signature))
    }

    @Test
    fun rejectsUnknownKeyAndModifiedTranscript() = runTest {
        val provider = CryptographyProvider.Default
        val eddsa = provider.get(EdDSA)
        val pair = eddsa.keyPairGenerator(EdDSA.Curve.Ed25519).generateKey()
        val publicKey = pair.publicKey.encodeToByteArray(EdDSA.PublicKey.Format.DER)
        val transcript = "canonical handshake transcript".encodeToByteArray()
        val signature = pair.privateKey.signatureGenerator().generateSignature(transcript)
        val verifier = PinnedEd25519HandshakeVerifier(
            trustedPublicKeys = mapOf("backend-key-v1" to publicKey),
            provider = provider
        )

        assertFalse(verifier.verify("untrusted-key", transcript, signature))
        assertFalse(verifier.verify("backend-key-v1", "tampered".encodeToByteArray(), signature))
        assertFalse(verifier.verify("backend-key-v1", transcript, ByteArray(63)))
    }
}
