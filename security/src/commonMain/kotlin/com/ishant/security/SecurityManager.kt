package com.ishant.security

import com.ishant.security.core.EncryptedPayload
import com.ishant.security.crypto.Aes256Gcm
import com.ishant.security.keys.RawAesKey
import com.ishant.security.serialization.SecurityJson
import kotlinx.serialization.KSerializer

/**
 * Convenience facade for byte arrays and kotlinx.serialization models.
 * All crypto operations are suspending because platform providers may be async.
 */
class SecurityManager(
    private val aes: Aes256Gcm = Aes256Gcm(),
    private val json: SecurityJson = SecurityJson(),
) {
    suspend fun encryptBytes(
        plaintext: ByteArray,
        key: RawAesKey,
        associatedData: ByteArray? = null,
    ): EncryptedPayload = aes.encrypt(plaintext, key, associatedData)

    suspend fun decryptBytes(
        payload: EncryptedPayload,
        key: RawAesKey,
        associatedData: ByteArray? = null,
    ): ByteArray = aes.decrypt(payload, key, associatedData)

    suspend fun encryptString(
        plaintext: String,
        key: RawAesKey,
        associatedData: ByteArray? = null,
    ): EncryptedPayload = encryptBytes(plaintext.encodeToByteArray(), key, associatedData)

    suspend fun decryptString(
        payload: EncryptedPayload,
        key: RawAesKey,
        associatedData: ByteArray? = null,
    ): String = decryptBytes(payload, key, associatedData).decodeToString()

    suspend fun <T> encryptObject(
        value: T,
        serializer: KSerializer<T>,
        key: RawAesKey,
        associatedData: ByteArray? = null,
    ): EncryptedPayload = encryptBytes(json.encode(serializer, value), key, associatedData)

    suspend fun <T> decryptObject(
        payload: EncryptedPayload,
        serializer: KSerializer<T>,
        key: RawAesKey,
        associatedData: ByteArray? = null,
    ): T = json.decode(serializer, decryptBytes(payload, key, associatedData))
}
