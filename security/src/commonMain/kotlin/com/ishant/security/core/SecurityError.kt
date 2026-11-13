package com.ishant.security.core

sealed class SecurityError(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    data class InvalidKeyLength(val actualBytes: Int) :
        SecurityError("AES-256 requires a 32-byte key; received $actualBytes bytes.")

    data class UnsupportedPayloadVersion(val version: Int) :
        SecurityError("Unsupported encrypted payload version: $version.")

    data class UnsupportedAlgorithm(val algorithm: String) :
        SecurityError("Unsupported encryption algorithm: $algorithm.")

    class InvalidHandshake(message: String) : SecurityError(message)
    data object HandshakeAuthenticationFailed : SecurityError("Server handshake signature verification failed.")
    class KeyAgreementFailed(cause: Throwable) : SecurityError("X25519 key agreement or HKDF failed.", cause)
    data object SessionClosed : SecurityError("Security session is closed.")
    data object SequenceExhausted : SecurityError("Session sequence exhausted; establish a new session.")
    class ReplayOrOutOfOrderMessage(expected: Long, actual: Long) :
        SecurityError("Replay or out-of-order message: expected $expected, got $actual.")

    data object InvalidPayload :
        SecurityError("Encrypted payload is empty or malformed.")

    class EncryptionFailed(cause: Throwable) :
        SecurityError("Encryption failed.", cause)

    class DecryptionFailed(cause: Throwable) :
        SecurityError("Decryption failed or authentication failed.", cause)
}
