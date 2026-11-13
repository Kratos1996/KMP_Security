package com.ishant.security.core

import kotlinx.serialization.Serializable

/**
 * Stable, versioned envelope. The ciphertext field is opaque provider output
 * containing the random nonce, ciphertext and GCM authentication tag.
 */
@Serializable
data class EncryptedPayload(
    val version: Int = CURRENT_VERSION,
    val algorithm: String = ALGORITHM,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is EncryptedPayload &&
            version == other.version &&
            algorithm == other.algorithm &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int =
        31 * (31 * version + algorithm.hashCode()) + ciphertext.contentHashCode()

    companion object {
        const val CURRENT_VERSION: Int = 1
        const val ALGORITHM: String = "AES-256-GCM"
    }
}
