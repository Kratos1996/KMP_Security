# KMP_Security

A Kotlin Multiplatform security foundation for Compose Multiplatform and native Android/iOS applications.

**Package:** `com.ishant.security`  
**Modules:**  
- `:security` — Core KMP library (cryptography, key abstractions, hardware identity, serialization helpers, handshake, and tests).  
- `:app` — Android Application with Jetpack Compose UI for interactive encryption/decryption and automated security checks.  
**Cipher:** AES-256-GCM  
**Handshake:** Ephemeral X25519 + HKDF-SHA256 + Ed25519 Transcript Signatures  
**Device Identity:** Android Keystore (Android) & Secure Enclave (iOS) P-256 ECDSA  

## Status

Security foundation with AES-256-GCM encryption and an authenticated ephemeral X25519 + HKDF-SHA256 handshake protocol. This repository is structured as a Kotlin Multiplatform library with a companion Android sample application.

## Project Architecture

```
KMP_Security/
├── security/                # Core KMP Security Library
│   ├── src/commonMain/      # AES-256-GCM, SecurityManager, Handshake, Session, Models
│   ├── src/androidMain/     # AndroidDeviceIdentityKeyStore (Android Keystore P-256 ECDSA)
│   ├── src/iosMain/         # IosDeviceIdentityKeyStore (Secure Enclave P-256 ECDSA)
│   └── src/commonTest/      # 20+ Cross-platform unit tests
└── app/                     # Android Demo & Interactive Testing App (Jetpack Compose)
    └── src/main/            # Interactive Encrypt/Decrypt tool + Hardware Keystore Demo
```

## Key Features

- **AES-256-GCM Authenticated Encryption:** Provider-generated fresh 96-bit nonces for every encryption operation.
- **Gradle-Driven Configuration:** `CURRENT_VERSION` (`1`) and `ALGORITHM` (`"AES-256-GCM"`) generated directly via Gradle `SecurityBuildConfig`.
- **Hardware-Backed Device Identity:** Non-exportable P-256 ECDSA signing key generation using Android Keystore and iOS Secure Enclave.
- **Authenticated Ephemeral Handshake:** X25519 key exchange with HKDF-SHA256 directional key derivation (`client-to-server` & `server-to-client`) and pinned Ed25519 server transcript signatures.
- **Replay & Sequence Defenses:** Session-bound AAD with strict sequence increments and replay blocking.
- **High-Level SecurityManager & JSON Helpers:** High-level object encryption for `@Serializable` Kotlin models using `kotlinx.serialization`.

## Basic Usage

### 1. Low-Level AES-256-GCM Operations

```kotlin
// Inside a suspend function or coroutine scope
val key = RawAesKey(keyBytes) // 32-byte key from secure key management
val aes = Aes256Gcm()

val encrypted: EncryptedPayload = aes.encrypt(
    plaintext = "sensitive payload".encodeToByteArray(),
    key = key,
    associatedData = "context:v1".encodeToByteArray(),
)

val decryptedBytes = aes.decrypt(
    payload = encrypted,
    key = key,
    associatedData = "context:v1".encodeToByteArray(),
)
```

### 2. High-Level SecurityManager & Object Serialization

```kotlin
val manager = SecurityManager()
val profile = UserProfile(userId = "usr_101", email = "user@example.com", roles = listOf("USER"))

// Encrypt Kotlin @Serializable Object
val encryptedPayload = manager.encryptObject(
    value = profile,
    serializer = UserProfile.serializer(),
    key = key,
    associatedData = "user_profile_context".encodeToByteArray(),
)

// Decrypt Kotlin Object
val decryptedProfile: UserProfile = manager.decryptObject(
    payload = encryptedPayload,
    serializer = UserProfile.serializer(),
    key = key,
    associatedData = "user_profile_context".encodeToByteArray(),
)
```

### 3. Android Hardware Device Identity Signing

```kotlin
val keyStore = AndroidDeviceIdentityKeyStore()
val identityKey = keyStore.getOrCreate() // Generates non-exportable P-256 ECDSA key in Android Keystore

val challengeSignature = keyStore.sign(challengeBytes)
// Send identityKey.keyId, identityKey.publicKeyDer, and challengeSignature to backend for verification
```

## Android Demo Application (`:app`)

The `:app` module provides a Jetpack Compose UI for testing the security library directly on an Android device or emulator:

- **Interactive Encrypt / Decrypt Tool:** Type custom text, encrypt using `AES-256-GCM`, copy JSON payload to Android Clipboard, paste ciphertext, and decrypt back to plaintext.
- **Automated Security Checks:** Runs hardware Keystore key generation, challenge signing, serialization, and X25519 handshake session tests with execution logs.

### Running the App

Select the **`app`** run configuration in Android Studio and deploy to your connected device/emulator, or build from the command line:

```bash
./gradlew :app:assembleDebug
```

## Build & Test Commands

Run unit tests across all common and platform targets:

```bash
# Run all unit tests in the security module
./gradlew :security:test

# Build Android App APK
./gradlew :app:assembleDebug
```

See [SECURITY.md](SECURITY.md), [SECURITY_PROTOCOL.md](SECURITY_PROTOCOL.md), and [CHANGELOG.md](CHANGELOG.md).
