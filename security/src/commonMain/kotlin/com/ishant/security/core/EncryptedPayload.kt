package com.ishant.security.core

import com.ishant.security.SecurityBuildConfig
import kotlinx.serialization.Serializable

/**
 * Stable, versioned envelope. The ciphertext field is opaque provider output
 * containing the random nonce, ciphertext and GCM authentication tag.
 */
@Serializable
data class EncryptedPayload(
    val version: Int = SecurityBuildConfig.CURRENT_VERSION,
    val algorithm: String = SecurityBuildConfig.ALGORITHM,
    val ciphertext: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        (other is EncryptedPayload) &&
            (version == other.version) &&
            (algorithm == other.algorithm) &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int =
        31 * (31 * version + algorithm.hashCode()) + ciphertext.contentHashCode()
}
