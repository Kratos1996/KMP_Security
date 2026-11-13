package com.ishant.security.keys

/**
 * Wrapper for externally provisioned AES key bytes.
 *
 * This class deliberately does not generate, persist, log, or fetch keys.
 * Supply key material from a trusted key-management layer. On mobile, prefer
 * platform-backed non-exportable key handles when the crypto adapter supports
 * them; do not treat this byte-array wrapper as secure storage.
 */
class RawAesKey(bytes: ByteArray) {
    internal val bytes: ByteArray = bytes.copyOf()

    internal fun clear() { bytes.fill(0) }

    override fun toString(): String = "RawAesKey([REDACTED])"
}
