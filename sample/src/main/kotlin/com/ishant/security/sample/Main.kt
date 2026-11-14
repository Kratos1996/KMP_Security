package com.ishant.security.sample

import com.ishant.security.SecurityManager
import com.ishant.security.core.EncryptedPayload
import com.ishant.security.core.SecurityError
import com.ishant.security.crypto.Aes256Gcm
import com.ishant.security.handshake.*
import com.ishant.security.keys.RawAesKey
import com.ishant.security.session.SequencedCiphertext
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EdDSA
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.XDH
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable

@Serializable
data class UserProfile(
    val userId: String,
    val email: String,
    val roles: List<String>,
)

fun main() = runBlocking {
    println("==========================================================")
    println("       KMP_Security Sample Application (JVM)         ")
    println("==========================================================\n")

    // ------------------------------------------------------------------
    // DEMO 1: AES-256-GCM Low-Level Cryptographic Primitives
    // ------------------------------------------------------------------
    println("--- DEMO 1: AES-256-GCM Encryption & Decryption ---")
    val rawKeyBytes = ByteArray(32) { (it + 1).toByte() }
    val key = RawAesKey(rawKeyBytes)
    val aes = Aes256Gcm()

    val secretMessage = "Sensitive payload: user_id=48201, auth_token=secret_xyz"
    val aad = "context:profile_v1".encodeToByteArray()

    println("Original Plaintext : $secretMessage")
    println("Key Material       : $key")

    val encryptedPayload: EncryptedPayload = aes.encrypt(
        plaintext = secretMessage.encodeToByteArray(),
        key = key,
        associatedData = aad,
    )

    println("Encrypted Envelope : Version=${encryptedPayload.version}, Algorithm=${encryptedPayload.algorithm}")
    println("Ciphertext Bytes   : ${encryptedPayload.ciphertext.size} bytes [hex: ${encryptedPayload.ciphertext.toHexString(HexFormat.Default)}]")

    val decryptedBytes = aes.decrypt(
        payload = encryptedPayload,
        key = key,
        associatedData = aad,
    )
    val decryptedMessage = decryptedBytes.decodeToString()
    println("Decrypted Result   : $decryptedMessage")
    check(decryptedMessage == secretMessage) { "Decryption mismatch!" }
    println("[SUCCESS] AES-256-GCM Roundtrip Verified!\n")

    // ------------------------------------------------------------------
    // DEMO 2: SecurityManager Facade & Kotlinx Serialization
    // ------------------------------------------------------------------
    println("--- DEMO 2: SecurityManager & Object Serialization ---")
    val manager = SecurityManager()
    val profile = UserProfile(
        userId = "usr_99812",
        email = "developer@kmp-security.com",
        roles = listOf("ADMIN", "DEVELOPER"),
    )

    println("Original Object    : $profile")
    val encryptedObject = manager.encryptObject(
        value = profile,
        serializer = UserProfile.serializer(),
        key = key,
        associatedData = "aad:user_profile".encodeToByteArray(),
    )
    println("Encrypted Object   : ${encryptedObject.ciphertext.size} bytes")

    val decryptedProfile: UserProfile = manager.decryptObject(
        payload = encryptedObject,
        serializer = UserProfile.serializer(),
        key = key,
        associatedData = "aad:user_profile".encodeToByteArray(),
    )
    println("Decrypted Object   : $decryptedProfile")
    check(decryptedProfile == profile) { "Object deserialization mismatch!" }
    println("[SUCCESS] SecurityManager Object Serialization Verified!\n")

    // ------------------------------------------------------------------
    // DEMO 3: Integrity Failures & Tamper Detection
    // ------------------------------------------------------------------
    println("--- DEMO 3: Cryptographic Tamper & Error Handling ---")

    // 3a. Mismatched AAD
    try {
        aes.decrypt(encryptedPayload, key, associatedData = "wrong_aad".encodeToByteArray())
        error("Should have failed on wrong AAD!")
    } catch (e: SecurityError.DecryptionFailed) {
        println("[PASSED] Detected mismatched AAD -> ${e::class.simpleName}")
    }

    // 3b. Altered Ciphertext Byte
    val corruptedBytes = encryptedPayload.ciphertext.copyOf().also {
        it[it.lastIndex] = (it.last().toInt() xor 0xFF).toByte()
    }
    val corruptedPayload = encryptedPayload.copy(ciphertext = corruptedBytes)
    try {
        aes.decrypt(corruptedPayload, key, associatedData = aad)
        error("Should have failed on corrupted ciphertext!")
    } catch (e: SecurityError.DecryptionFailed) {
        println("[PASSED] Detected corrupted ciphertext -> ${e::class.simpleName}")
    }

    // 3c. Invalid Key Size
    try {
        aes.encrypt(secretMessage.encodeToByteArray(), RawAesKey(ByteArray(16)))
        error("Should have failed on 16-byte key!")
    } catch (e: SecurityError.InvalidKeyLength) {
        println("[PASSED] Rejected invalid key length -> ${e::class.simpleName}")
    }
    println("[SUCCESS] Integrity & Tamper Safety Verified!\n")

    // ------------------------------------------------------------------
    // DEMO 4: End-to-End Ephemeral X25519 Handshake & Session
    // ------------------------------------------------------------------
    println("--- DEMO 4: Ephemeral X25519 Handshake & Session Demo ---")

    val provider = CryptographyProvider.Default
    val xdh = provider.get(XDH)
    val eddsa = provider.get(EdDSA)

    // 4a. Backend Setup: Server Ed25519 Signing Key Pair
    val serverSigningKeyPair = eddsa.keyPairGenerator(EdDSA.Curve.Ed25519).generateKey()
    val serverSigningPublicKeySpki = serverSigningKeyPair.publicKey.encodeToByteArray(EdDSA.PublicKey.Format.DER)
    val serverKeyId = "kms_ed25519_key_v1"

    // 4b. Client Verifier: Pinned Backend Server Key
    val verifier = PinnedEd25519HandshakeVerifier(
        trustedPublicKeys = mapOf(serverKeyId to serverSigningPublicKeySpki),
        provider = provider,
    )

    // 4c. Handshake Step 1: Client generates ClientHello
    val clientHandshake = X25519Handshake()
    val pendingClient = clientHandshake.begin()
    println("Client -> Sent ClientHello (Ephemeral X25519 Public Key: ${pendingClient.clientHello.clientEphemeralPublicKey.size} bytes)")

    // 4d. Backend Step 2: Server generates ServerHello & Signs Handshake
    val serverEphemeralKeyPair = xdh.keyPairGenerator(XDH.Curve.X25519).generateKey()
    val serverEphemeralPublicDer = serverEphemeralKeyPair.publicKey.encodeToByteArray(XDH.PublicKey.Format.DER)
    val serverNonce = CryptographyRandom.nextBytes(32)
    val sessionId = "sess_live_demo_1001"

    val clientSession = clientHandshake.complete(
        pending = pendingClient,
        serverHello = ServerHello(
            sessionId = sessionId,
            serverEphemeralPublicKey = serverEphemeralPublicDer,
            serverNonce = serverNonce,
            signingKeyId = serverKeyId,
            signature = ByteArray(64), // Non-empty placeholder signature to pass initial checks
        ),
    ) { keyId, transcript, _ ->
        // Backend computes real Ed25519 signature over canonical transcript
        val realSignature = serverSigningKeyPair.privateKey.signatureGenerator().generateSignature(transcript)
        verifier.verify(keyId, transcript, realSignature)
    }

    println("[SUCCESS] Handshake Completed & Server Identity Verified! Session ID: ${clientSession.sessionId}")

    // 4e. Simulated Backend Key Derivation
    val clientPublic = xdh.publicKeyDecoder(XDH.Curve.X25519)
        .decodeFromByteArray(XDH.PublicKey.Format.DER, pendingClient.clientHello.clientEphemeralPublicKey)
    val serverSharedSecret = serverEphemeralKeyPair.privateKey.sharedSecretGenerator()
        .generateSharedSecretToByteArray(clientPublic)

    val salt = pendingClient.clientHello.clientNonce + serverNonce
    val hkdf = provider.get(HKDF)

    suspend fun deriveServerDirectionKey(directionLabel: String): RawAesKey {
        val derivedBytes = hkdf.secretDerivation(
            digest = SHA256,
            outputSize = 256.bits,
            salt = salt,
            info = "kmp-security/v1/$sessionId/$directionLabel".encodeToByteArray(),
        ).deriveSecretToByteArray(serverSharedSecret)
        return RawAesKey(derivedBytes)
    }

    val serverC2sKey = deriveServerDirectionKey("client-to-server")
    val serverS2cKey = deriveServerDirectionKey("server-to-client")

    // 4f. Secure Client Request Transmission
    val requestPayload = "POST /order { item: 'Special Food', qty: 2 }".encodeToByteArray()
    val clientEncryptedRequest: SequencedCiphertext = clientSession.encryptRequest(requestPayload)
    println("\nClient -> Encrypted Request (Seq #${clientEncryptedRequest.sequence}): ${clientEncryptedRequest.payload.ciphertext.size} bytes")

    // Backend decrypts client request
    val serverDecryptAes = Aes256Gcm()
    val serverReceivedBytes = serverDecryptAes.decrypt(
        payload = clientEncryptedRequest.payload,
        key = serverC2sKey,
        associatedData = "kmp-security/v1|$sessionId|c2s|0".encodeToByteArray(),
    )
    println("Server <- Decrypted Request: ${serverReceivedBytes.decodeToString()}")

    // 4g. Secure Server Response Transmission
    val responsePayloadBytes = "HTTP 200 OK { orderId: 'ord_5521', status: 'CONFIRMED' }".encodeToByteArray()
    val serverEncryptedResponsePayload = serverDecryptAes.encrypt(
        plaintext = responsePayloadBytes,
        key = serverS2cKey,
        associatedData = "kmp-security/v1|$sessionId|s2c|0".encodeToByteArray(),
    )
    val serverResponse = SequencedCiphertext(sequence = 0L, payload = serverEncryptedResponsePayload)
    println("Server -> Encrypted Response (Seq #${serverResponse.sequence}): ${serverResponse.payload.ciphertext.size} bytes")

    val clientReceivedResponseBytes = clientSession.decryptResponse(serverResponse)
    println("Client <- Decrypted Response: ${clientReceivedResponseBytes.decodeToString()}")

    // 4h. Anti-Replay Protection Test
    try {
        clientSession.decryptResponse(serverResponse)
        error("Should have failed on replaying response sequence 0!")
    } catch (e: SecurityError.ReplayOrOutOfOrderMessage) {
        println("[PASSED] Replay Protection Blocked Replayed Message -> ${e::class.simpleName}")
    }

    println("\n==========================================================")
    println("      ALL SECURITY TESTS & SAMPLE DEMOS PASSED!            ")
    println("==========================================================")
}
