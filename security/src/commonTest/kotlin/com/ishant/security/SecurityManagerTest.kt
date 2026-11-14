package com.ishant.security

import com.ishant.security.core.SecurityError
import com.ishant.security.keys.RawAesKey
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SecurityManagerTest {
    private val manager = SecurityManager()
    private val key = RawAesKey(ByteArray(32) { (it + 1).toByte() })

    @Test
    fun encryptDecryptStringRoundTrip() = runTest {
        val clear = "sensitive user information"
        val encrypted = manager.encryptString(clear, key)
        assertEquals(clear, manager.decryptString(encrypted, key))
    }

    @Test
    fun encryptedPayloadUsesVersionedAlgorithm() = runTest {
        val encrypted = manager.encryptBytes(byteArrayOf(1, 2, 3), key)
        assertEquals(SecurityBuildConfig.CURRENT_VERSION, encrypted.version)
        assertEquals(SecurityBuildConfig.ALGORITHM, encrypted.algorithm)
    }

    @Test
    fun eachEncryptionUsesFreshRandomIv() = runTest {
        val clear = "same message".encodeToByteArray()
        val first = manager.encryptBytes(clear, key)
        val second = manager.encryptBytes(clear, key)
        assertEquals(false, first.ciphertext.contentEquals(second.ciphertext))
    }

    @Test
    fun wrongAadFailsAuthentication() = runTest {
        val encrypted = manager.encryptBytes(
            byteArrayOf(9, 8, 7), key, "account:1".encodeToByteArray()
        )
        assertFailsWith<SecurityError.DecryptionFailed> {
            manager.decryptBytes(encrypted, key, "account:2".encodeToByteArray())
        }
    }

    @Test
    fun alteredCiphertextFailsAuthentication() = runTest {
        val encrypted = manager.encryptBytes(byteArrayOf(4, 5, 6), key)
        val altered = encrypted.copy(ciphertext = encrypted.ciphertext.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        })
        assertFailsWith<SecurityError.DecryptionFailed> {
            manager.decryptBytes(altered, key)
        }
    }

    @Test
    fun invalidKeyLengthIsRejected() = runTest {
        assertFailsWith<SecurityError.InvalidKeyLength> {
            manager.encryptBytes(byteArrayOf(1), RawAesKey(ByteArray(16)))
        }
    }

    @Test
    fun byteArrayRoundTrip() = runTest {
        val bytes = ByteArray(256) { it.toByte() }
        val encrypted = manager.encryptBytes(bytes, key)
        assertContentEquals(bytes, manager.decryptBytes(encrypted, key))
    }
}
