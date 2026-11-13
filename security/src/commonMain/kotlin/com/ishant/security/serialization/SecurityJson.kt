package com.ishant.security.serialization

import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

/**
 * Shared JSON configuration for security payloads and serializable models.
 * Unknown keys are ignored to support additive backend fields.
 */
class SecurityJson(
    private val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }
) {
    fun <T> encode(serializer: KSerializer<T>, value: T): ByteArray =
        json.encodeToString(serializer, value).encodeToByteArray()

    fun <T> decode(serializer: KSerializer<T>, bytes: ByteArray): T =
        json.decodeFromString(serializer, bytes.decodeToString())
}
