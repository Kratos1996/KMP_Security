package com.ishant.security.preferences

/**
 * Configuration for one logical encrypted preferences namespace.
 *
 * Names are stable identifiers and should not contain secrets.
 */
data class SecurePreferencesConfig(
    val name: String = "secure_preferences",
    val keyAlias: String = "com.ishant.security.preferences.master.v1",
) {
    init {
        require(name.isNotBlank()) { "Preferences name cannot be blank" }
        require(keyAlias.isNotBlank()) { "Key alias cannot be blank" }
    }
}
