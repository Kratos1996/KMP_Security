package com.ishant.security.device

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Android implementation backed by AndroidKeyStore.
 *
 * The EC private key is generated and used inside Android Keystore and is never
 * returned by this class. The public key is exported as DER SubjectPublicKeyInfo.
 */
class AndroidDeviceIdentityKeyStore(
    private val alias: String = DEFAULT_ALIAS
) : DeviceIdentityKeyStore {

    init {
        require(alias.isNotBlank()) { "Keystore alias cannot be blank" }
    }

    override suspend fun getOrCreate(): DeviceIdentityPublicKey = withContext(Dispatchers.IO) {
        synchronized(LOCK) {
            val keyStore = loadKeyStore()
            if (!keyStore.containsAlias(alias)) {
                generateKeyPair()
            }

            val certificate = keyStore.getCertificate(alias)
                ?: error("Android Keystore identity certificate is missing")
            val publicKeyDer = certificate.publicKey.encoded
                ?: error("Android Keystore did not provide an encoded public key")

            DeviceIdentityPublicKey(
                keyId = publicKeyDer.toKeyId(),
                publicKeyDer = publicKeyDer.copyOf()
            )
        }
    }

    override suspend fun sign(challenge: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        require(challenge.size in MIN_CHALLENGE_SIZE..MAX_CHALLENGE_SIZE) {
            "Challenge must contain 16..4096 bytes"
        }

        synchronized(LOCK) {
            val keyStore = loadKeyStore()
            val privateKey = keyStore.getKey(alias, null)
                ?: error("Device identity key does not exist; call getOrCreate first")

            val signer = Signature.getInstance(SIGNATURE)
            signer.initSign(privateKey as java.security.PrivateKey)
            signer.update(challenge)
            signer.sign()
        }
    }

    override suspend fun delete() = withContext(Dispatchers.IO) {
        synchronized(LOCK) {
            loadKeyStore().deleteEntry(alias)
        }
    }

    private fun generateKeyPair() {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()

        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun ByteArray.toKeyId(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(this)
        return digest.joinToString(separator = "") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
    }

    private companion object {
        const val DEFAULT_ALIAS = "kmp.security.device.identity.p256.v1"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val EC_CURVE = "secp256r1"
        const val SIGNATURE = "SHA256withECDSA"
        const val MIN_CHALLENGE_SIZE = 16
        const val MAX_CHALLENGE_SIZE = 4096
        val LOCK = Any()
    }
}
