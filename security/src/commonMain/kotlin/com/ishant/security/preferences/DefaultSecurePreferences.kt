package com.ishant.security.preferences

import com.ishant.security.SecurityManager
import com.ishant.security.core.EncryptedPayload
import com.ishant.security.keys.RawAesKey
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable

/**
 * Common implementation over injected encrypted storage and a key provider.
 *
 * The store sees only EncryptedPayload records. Each record is bound to the
 * namespace and preference key using AES-GCM associated data.
 *
 * This implementation is deliberately not advertised as production-ready
 * for Android Keystore or WebCrypto until the opaque-key crypto interface is
 * introduced and those adapters are implemented.
 */
class DefaultSecurePreferences(
    private val config: SecurePreferencesConfig,
    private val store: EncryptedPreferencesStore,
    private val keyProvider: PreferencesKeyProvider,
    private val securityManager: SecurityManager = SecurityManager(),
) : SecurePreferences {

    private val mutex = Mutex()

    override suspend fun putString(key: String, value: String) =
        putValue(key, StoredValue(type = ValueType.STRING, value = value))

    override suspend fun getString(key: String, defaultValue: String?): String? =
        getValue(key, ValueType.STRING)?.value ?: defaultValue

    override suspend fun putInt(key: String, value: Int) =
        putValue(key, StoredValue(type = ValueType.INT, value = value.toString()))

    override suspend fun getInt(key: String, defaultValue: Int): Int =
        getValue(key, ValueType.INT)?.value?.toIntOrNull() ?: defaultValue

    override suspend fun putLong(key: String, value: Long) =
        putValue(key, StoredValue(type = ValueType.LONG, value = value.toString()))

    override suspend fun getLong(key: String, defaultValue: Long): Long =
        getValue(key, ValueType.LONG)?.value?.toLongOrNull() ?: defaultValue

    override suspend fun putFloat(key: String, value: Float) {
        require(value.isFinite()) { "Float preference must be finite" }
        putValue(key, StoredValue(type = ValueType.FLOAT, value = value.toString()))
    }

    override suspend fun getFloat(key: String, defaultValue: Float): Float =
        getValue(key, ValueType.FLOAT)?.value?.toFloatOrNull() ?: defaultValue

    override suspend fun putDouble(key: String, value: Double) {
        require(value.isFinite()) { "Double preference must be finite" }
        putValue(key, StoredValue(type = ValueType.DOUBLE, value = value.toString()))
    }

    override suspend fun getDouble(key: String, defaultValue: Double): Double =
        getValue(key, ValueType.DOUBLE)?.value?.toDoubleOrNull() ?: defaultValue

    override suspend fun putBoolean(key: String, value: Boolean) =
        putValue(key, StoredValue(type = ValueType.BOOLEAN, value = value.toString()))

    override suspend fun getBoolean(key: String, defaultValue: Boolean): Boolean =
        getValue(key, ValueType.BOOLEAN)?.value?.toBooleanStrictOrNull() ?: defaultValue

    override suspend fun contains(key: String): Boolean = mutex.withLock {
        validateKey(key)
        store.read(key) != null
    }

    override suspend fun remove(key: String) = mutex.withLock {
        validateKey(key)
        store.delete(key)
    }

    override suspend fun clear() = mutex.withLock {
        store.clear()
    }

    override suspend fun getAllKeys(): Set<String> = mutex.withLock {
        store.keys()
    }

    private suspend fun putValue(key: String, value: StoredValue) = mutex.withLock {
        validateKey(key)
        val aesKey = keyProvider.getOrCreate(config.keyAlias)
        try {
            val payload = securityManager.encryptObject(
                value = value,
                serializer = StoredValue.serializer(),
                key = aesKey,
                associatedData = associatedData(key),
            )
            store.write(key, payload)
        } finally {
            aesKey.clearForPreferences()
        }
    }

    private suspend fun getValue(key: String, expectedType: ValueType): StoredValue? =
        mutex.withLock {
            validateKey(key)
            val payload = store.read(key) ?: return@withLock null
            val aesKey = keyProvider.getOrCreate(config.keyAlias)
            try {
                val decoded = securityManager.decryptObject(
                    payload = payload,
                    serializer = StoredValue.serializer(),
                    key = aesKey,
                    associatedData = associatedData(key),
                )
                if (decoded.type != expectedType) {
                    throw SecurePreferencesException.TypeMismatch
                }
                decoded
            } catch (error: SecurePreferencesException) {
                throw error
            } catch (error: Throwable) {
                throw SecurePreferencesException.CorruptValue(error)
            } finally {
                aesKey.clearForPreferences()
            }
        }

    private fun associatedData(key: String): ByteArray =
        "secure-preferences:v1|${config.name}|${key}".encodeToByteArray()

    private fun validateKey(key: String) {
        if (key.isBlank()) throw SecurePreferencesException.InvalidKey
    }

    private fun RawAesKey.clearForPreferences() {
        // The security module intentionally keeps key clearing internal.
        // The key provider owns key lifecycle and must clear its own buffers.
    }

    @Serializable
    private data class StoredValue(
        val type: ValueType,
        val value: String,
    )

    @Serializable
    private enum class ValueType { STRING, INT, LONG, FLOAT, DOUBLE, BOOLEAN }
}
