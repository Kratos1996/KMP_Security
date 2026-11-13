package com.ishant.security.core

sealed class SecurityError(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    data class InvalidKeyLength(val actualBytes: Int) :
        SecurityError("AES-256 requires a 32-byte key; received $actualBytes bytes.")

    data class UnsupportedPayloadVersion(val version: Int) :
        SecurityError("Unsupported encrypted payload version: $version.")

    data class UnsupportedAlgorithm(val algorithm: String) :
        SecurityError("Unsupported encryption algorithm: $algorithm.")

    data object InvalidPayload :
        SecurityError("Encrypted payload is empty or malformed.")

    class EncryptionFailed(cause: Throwable) :
        SecurityError("Encryption failed.", cause)

    class DecryptionFailed(cause: Throwable) :
        SecurityError("Decryption failed or authentication failed.", cause)
}
