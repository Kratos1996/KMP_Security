package com.ishant.security.preferences

import com.ishant.security.core.EncryptedPayload
import com.ishant.security.keys.RawAesKey

/**
 * Storage contains ciphertext only. Implementations must provide atomic writes
 * and serialize concurrent mutations for a namespace.
 */
interface EncryptedPreferencesStore {
    suspend fun read(key: String): EncryptedPayload?
    suspend fun write(key: String, value: EncryptedPayload)
    suspend fun delete(key: String)
    suspend fun clear()
    suspend fun keys(): Set<String>
}

/**
 * Supplies encryption key material for the current platform.
 *
 * IMPORTANT: RawAesKey is a transitional common interface. Production
 * Android Keystore and browser WebCrypto implementations must use opaque
 * key handles and a platform crypto adapter rather than exporting keys to
 * common Kotlin. Do not implement this by reusing DeviceIdentityKeyStore.
 */
interface PreferencesKeyProvider {
    suspend fun getOrCreate(alias: String): RawAesKey
    suspend fun delete(alias: String)
}

/**
 * Errors are explicit so authentication failures are never silently treated
 * as missing preferences or default values.
 */
sealed class SecurePreferencesException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    data object InvalidKey : SecurePreferencesException("Preference key cannot be blank.")
    data object TypeMismatch : SecurePreferencesException("Stored preference has a different value type.")
    class CorruptValue(cause: Throwable) :
        SecurePreferencesException("Stored preference is corrupted or failed authentication.", cause)
}
