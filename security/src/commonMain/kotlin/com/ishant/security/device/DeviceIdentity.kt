package com.ishant.security.device

import kotlinx.serialization.Serializable

/**
 * Platform adapter contract for a long-lived installation identity.
 *
 * Implementations must generate the private key inside Android Keystore / an
 * appropriate iOS Keychain-backed or Secure Enclave-backed facility and must
 * never export private key bytes. This common module deliberately does not
 * provide an insecure software-key fallback.
 */
interface DeviceIdentityKeyStore {
    /** Returns the existing installation key or creates it exactly once. */
    suspend fun getOrCreate(): DeviceIdentityPublicKey

    /** Signs a server-provided, single-use registration/authentication challenge. */
    suspend fun sign(challenge: ByteArray): ByteArray

    /** Deletes the local identity only for explicit device de-registration/reset. */
    suspend fun delete()
}

@Serializable
data class DeviceIdentityPublicKey(
    val keyId: String,
    /** DER SubjectPublicKeyInfo encoded P-256 public key. */
    val publicKeyDer: ByteArray,
    val algorithm: String = SIGNATURE_ALGORITHM
) {
    init {
        require(keyId.isNotBlank() && keyId.length <= MAX_KEY_ID_LENGTH) {
            "Invalid device key id"
        }
        require(publicKeyDer.isNotEmpty()) { "Device public key cannot be empty" }
        require(algorithm == SIGNATURE_ALGORITHM) { "Unsupported device signature algorithm" }
    }

    companion object {
        const val SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256"
        const val MAX_KEY_ID_LENGTH = 128
    }
}

/** Public data sent to the backend when registering an installation. */
@Serializable
data class DeviceIdentityRegistration(
    val keyId: String,
    val publicKeyDer: ByteArray,
    val algorithm: String = DeviceIdentityPublicKey.SIGNATURE_ALGORITHM
)

/**
 * Stateless helper that creates a registration payload and signs a fresh
 * backend challenge. The challenge must be obtained over authenticated TLS,
 * be unpredictable, single-use and short-lived on the backend.
 */
class DeviceIdentityManager(
    private val keyStore: DeviceIdentityKeyStore
) {
    suspend fun registration(): DeviceIdentityRegistration {
        val identity = keyStore.getOrCreate()
        return DeviceIdentityRegistration(
            keyId = identity.keyId,
            publicKeyDer = identity.publicKeyDer.copyOf(),
            algorithm = identity.algorithm
        )
    }

    suspend fun signChallenge(challenge: ByteArray): ByteArray {
        require(challenge.size in MIN_CHALLENGE_SIZE..MAX_CHALLENGE_SIZE) {
            "Challenge must contain 16..4096 bytes"
        }
        val signature = keyStore.sign(challenge.copyOf())
        check(signature.isNotEmpty()) { "Platform keystore returned an empty signature" }
        return signature
    }

    private companion object {
        const val MIN_CHALLENGE_SIZE = 16
        const val MAX_CHALLENGE_SIZE = 4096
    }
}
