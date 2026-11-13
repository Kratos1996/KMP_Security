package com.ishant.security.device

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DeviceIdentityManagerTest {

    @Test
    fun registrationReturnsCopyOfPublicKey() = runTest {
        val sourceKey = byteArrayOf(1, 2, 3, 4)
        val store = FakeDeviceIdentityKeyStore(sourceKey)
        val manager = DeviceIdentityManager(store)

        val registration = manager.registration()
        sourceKey[0] = 99

        assertEquals("test-key-id", registration.keyId)
        assertContentEquals(byteArrayOf(1, 2, 3, 4), registration.publicKeyDer)
        assertEquals(DeviceIdentityPublicKey.SIGNATURE_ALGORITHM, registration.algorithm)
    }

    @Test
    fun challengeMustBeBetween16And4096Bytes() = runTest {
        val store = FakeDeviceIdentityKeyStore(byteArrayOf(1))
        val manager = DeviceIdentityManager(store)

        assertFailsWith<IllegalArgumentException> {
            manager.signChallenge(ByteArray(15))
        }
        assertFailsWith<IllegalArgumentException> {
            manager.signChallenge(ByteArray(4097))
        }
        assertTrue(store.lastSignedChallenge == null)
    }

    @Test
    fun validChallengeIsPassedToPlatformStore() = runTest {
        val store = FakeDeviceIdentityKeyStore(byteArrayOf(1))
        val manager = DeviceIdentityManager(store)
        val challenge = ByteArray(32) { it.toByte() }

        val signature = manager.signChallenge(challenge)

        assertContentEquals(challenge, store.lastSignedChallenge)
        assertContentEquals(byteArrayOf(7, 8, 9), signature)
    }

    private class FakeDeviceIdentityKeyStore(
        private val publicKey: ByteArray
    ) : DeviceIdentityKeyStore {
        var lastSignedChallenge: ByteArray? = null

        override suspend fun getOrCreate() = DeviceIdentityPublicKey(
            keyId = "test-key-id",
            publicKeyDer = publicKey
        )

        override suspend fun sign(challenge: ByteArray): ByteArray {
            lastSignedChallenge = challenge.copyOf()
            return byteArrayOf(7, 8, 9)
        }

        override suspend fun delete() = Unit
    }
}
