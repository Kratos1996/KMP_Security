package com.ishant.security.device

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * JVM / Desktop implementation of [DeviceIdentityKeyStore].
 *
 * Backed by Java Cryptography Architecture (JCA) using ECDSA P-256 (secp256r1)
 * and SHA-256 challenge signing.
 *
 * @param alias Identifier for this installation identity.
 * @param storageDirectory Optional directory to persist public/private key material.
 *                         If null, the identity remains in-memory for the JVM process lifecycle.
 */
class JvmDeviceIdentityKeyStore(
    private val alias: String = DEFAULT_ALIAS,
    private val storageDirectory: File? = null,
) : DeviceIdentityKeyStore {

    init {
        require(alias.isNotBlank()) { "Identity alias cannot be blank" }
    }

    private var cachedKeyPair: KeyPair? = null
    private val lock = Any()

    @Throws(Throwable::class)
    override suspend fun getOrCreate(): DeviceIdentityPublicKey = withContext(Dispatchers.IO) {
        synchronized(lock) {
            val keyPair = cachedKeyPair
                ?: loadFromDisk()
                ?: generateKeyPair().also { pair ->
                    cachedKeyPair = pair
                    saveToDisk(pair)
                }

            val publicKeyDer = keyPair.public.encoded
                ?: error("JVM JCA provider did not provide an encoded public key")

            DeviceIdentityPublicKey(
                keyId = publicKeyDer.toKeyId(),
                publicKeyDer = publicKeyDer.copyOf()
            )
        }
    }

    @Throws(Throwable::class)
    override suspend fun sign(challenge: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        require(challenge.size in MIN_CHALLENGE_SIZE..MAX_CHALLENGE_SIZE) {
            "Challenge must contain 16..4096 bytes"
        }

        synchronized(lock) {
            val keyPair = cachedKeyPair
                ?: loadFromDisk()
                ?: error("Device identity key does not exist; call getOrCreate first")

            val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
            signer.initSign(keyPair.private)
            signer.update(challenge)
            signer.sign()
        }
    }

    @Throws(Throwable::class)
    override suspend fun delete() = withContext(Dispatchers.IO) {
        synchronized(lock) {
            cachedKeyPair = null
            if (storageDirectory != null && storageDirectory.exists()) {
                val privFile = File(storageDirectory, "$alias.key")
                val pubFile = File(storageDirectory, "$alias.pub")
                if (privFile.exists()) privFile.delete()
                if (pubFile.exists()) pubFile.delete()
            }
        }
    }

    private fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        generator.initialize(ECGenParameterSpec(EC_CURVE))
        return generator.generateKeyPair()
    }

    private fun loadFromDisk(): KeyPair? {
        val dir = storageDirectory ?: return null
        val privFile = File(dir, "$alias.key")
        val pubFile = File(dir, "$alias.pub")
        if (!privFile.exists() || !pubFile.exists()) return null

        return try {
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
            val privBytes = privFile.readBytes()
            val pubBytes = pubFile.readBytes()
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privBytes))
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(pubBytes))
            KeyPair(publicKey, privateKey).also { cachedKeyPair = it }
        } catch (_: Exception) {
            null
        }
    }

    private fun saveToDisk(pair: KeyPair) {
        val dir = storageDirectory ?: return
        if (!dir.exists()) {
            dir.mkdirs()
        }
        val privFile = File(dir, "$alias.key")
        val pubFile = File(dir, "$alias.pub")
        privFile.writeBytes(pair.private.encoded)
        pubFile.writeBytes(pair.public.encoded)
    }

    private fun ByteArray.toKeyId(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(this)
        return digest.joinToString(separator = "") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
    }

    private companion object {
        const val DEFAULT_ALIAS = "kmp.security.device.identity.jvm.p256.v1"
        const val KEY_ALGORITHM = "EC"
        const val EC_CURVE = "secp256r1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val MIN_CHALLENGE_SIZE = 16
        const val MAX_CHALLENGE_SIZE = 4096
    }
}
