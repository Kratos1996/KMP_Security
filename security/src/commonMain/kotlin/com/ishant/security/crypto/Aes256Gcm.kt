package com.ishant.security.crypto

import com.ishant.security.SecurityBuildConfig
import com.ishant.security.core.EncryptedPayload
import com.ishant.security.core.SecurityError
import com.ishant.security.keys.RawAesKey
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import kotlin.coroutines.cancellation.CancellationException

/**
 * AES-256-GCM operations.
 *
 * The provider's default encrypt() API creates a fresh random IV and prefixes it
 * to the returned ciphertext. The resulting payload therefore carries the IV,
 * encrypted bytes and authentication tag as one opaque byte sequence.
 */
class Aes256Gcm {
    private val aesGcm = CryptographyProvider.Default.get(AES.GCM)

    @Throws(SecurityError::class, CancellationException::class)
    suspend fun encrypt(
        plaintext: ByteArray,
        key: RawAesKey,
        associatedData: ByteArray? = null
    ): EncryptedPayload {
        validateKey(key)
        return try {
            val decodedKey = aesGcm.keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, key.bytes.copyOf())
            val encrypted = decodedKey.cipher().encrypt(
                plaintext = plaintext,
                associatedData = associatedData
            )
            EncryptedPayload(ciphertext = encrypted)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (cause: Throwable) {
            throw SecurityError.EncryptionFailed(cause)
        }
    }

    @Throws(SecurityError::class, CancellationException::class)
    suspend fun decrypt(
        payload: EncryptedPayload,
        key: RawAesKey,
        associatedData: ByteArray? = null
    ): ByteArray {
        validateKey(key)
        if (payload.version != SecurityBuildConfig.CURRENT_VERSION) {
            throw SecurityError.UnsupportedPayloadVersion(payload.version)
        }
        if (payload.algorithm != SecurityBuildConfig.ALGORITHM) {
            throw SecurityError.UnsupportedAlgorithm(payload.algorithm)
        }
        if (payload.ciphertext.isEmpty()) {
            throw SecurityError.InvalidPayload
        }

        return try {
            val decodedKey = aesGcm.keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, key.bytes.copyOf())
            decodedKey.cipher().decrypt(
                ciphertext = payload.ciphertext,
                associatedData = associatedData
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (cause: Throwable) {
            throw SecurityError.DecryptionFailed(cause)
        }
    }

    private fun validateKey(key: RawAesKey) {
        if (key.bytes.size != AES_256_KEY_BYTES) {
            throw SecurityError.InvalidKeyLength(key.bytes.size)
        }
    }

    private companion object {
        const val AES_256_KEY_BYTES = 32
    }
}
