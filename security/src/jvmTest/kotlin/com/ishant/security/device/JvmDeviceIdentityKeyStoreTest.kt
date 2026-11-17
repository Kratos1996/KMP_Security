package com.ishant.security.device

import kotlinx.coroutines.test.runTest
import java.io.File
import java.nio.file.Files
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.test.*

class JvmDeviceIdentityKeyStoreTest {

    @Test
    fun getOrCreateGeneratesValidP256Key() = runTest {
        val keyStore = JvmDeviceIdentityKeyStore()
        val identity = keyStore.getOrCreate()

        assertNotNull(identity.keyId)
        assertEquals(64, identity.keyId.length)
        assertTrue(identity.publicKeyDer.isNotEmpty())
        assertEquals(DeviceIdentityPublicKey.SIGNATURE_ALGORITHM, identity.algorithm)

        // Idempotent call returns identical key
        val second = keyStore.getOrCreate()
        assertEquals(identity.keyId, second.keyId)
        assertContentEquals(identity.publicKeyDer, second.publicKeyDer)
    }

    @Test
    fun signProducesValidEcdsaSignature() = runTest {
        val keyStore = JvmDeviceIdentityKeyStore()
        val identity = keyStore.getOrCreate()
        val challenge = "challenge_nonce_for_jvm_test_987".encodeToByteArray()

        val signature = keyStore.sign(challenge)
        assertTrue(signature.isNotEmpty())

        // Verify mathematically using JCA verifier
        val keyFactory = KeyFactory.getInstance("EC")
        val pubKey = keyFactory.generatePublic(X509EncodedKeySpec(identity.publicKeyDer))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(pubKey)
        verifier.update(challenge)
        assertTrue(verifier.verify(signature), "Signature must verify against generated public key")
    }

    @Test
    fun invalidChallengeSizeThrows() = runTest {
        val keyStore = JvmDeviceIdentityKeyStore()
        keyStore.getOrCreate()

        assertFailsWith<IllegalArgumentException> {
            keyStore.sign(ByteArray(15))
        }
        assertFailsWith<IllegalArgumentException> {
            keyStore.sign(ByteArray(4097))
        }
    }

    @Test
    fun persistenceToDirectoryWorks() = runTest {
        val tempDir = Files.createTempDirectory("jvm-keystore-test").toFile()
        try {
            val store1 = JvmDeviceIdentityKeyStore(storageDirectory = tempDir)
            val identity1 = store1.getOrCreate()
            val challenge = "challenge_persisted_test_123".encodeToByteArray()
            val sig1 = store1.sign(challenge)

            // Re-instantiate pointing to the same folder
            val store2 = JvmDeviceIdentityKeyStore(storageDirectory = tempDir)
            val identity2 = store2.getOrCreate()

            assertEquals(identity1.keyId, identity2.keyId)
            assertContentEquals(identity1.publicKeyDer, identity2.publicKeyDer)

            // Test deletion
            store2.delete()
            assertFalse(File(tempDir, "kmp.security.device.identity.jvm.p256.v1.key").exists())
        } finally {
            tempDir.deleteRecursively()
        }
    }
}
