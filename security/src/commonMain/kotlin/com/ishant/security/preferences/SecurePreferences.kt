package com.ishant.security.preferences

/**
 * SharedPreferences-style encrypted key/value API.
 *
 * All operations are suspending because crypto providers and secure platform
 * stores may be asynchronous. Implementations must never persist plaintext.
 */
interface SecurePreferences {
    suspend fun putString(key: String, value: String)
    suspend fun getString(key: String, defaultValue: String? = null): String?

    suspend fun putInt(key: String, value: Int)
    suspend fun getInt(key: String, defaultValue: Int = 0): Int

    suspend fun putLong(key: String, value: Long)
    suspend fun getLong(key: String, defaultValue: Long = 0L): Long

    suspend fun putFloat(key: String, value: Float)
    suspend fun getFloat(key: String, defaultValue: Float = 0f): Float

    suspend fun putDouble(key: String, value: Double)
    suspend fun getDouble(key: String, defaultValue: Double = 0.0): Double

    suspend fun putBoolean(key: String, value: Boolean)
    suspend fun getBoolean(key: String, defaultValue: Boolean = false): Boolean

    suspend fun contains(key: String): Boolean
    suspend fun remove(key: String)
    suspend fun clear()
    suspend fun getAllKeys(): Set<String>
}
