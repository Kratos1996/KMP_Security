# KMP_Security

[![Maven Central](https://img.shields.io/maven-central/v/io.github.kratos1996/kmp-security)](https://central.sonatype.com/artifact/io.github.kratos1996/kmp-security)
[![](https://jitpack.io/v/Kratos1996/KMP_Security.svg)](https://jitpack.io/#Kratos1996/KMP_Security)
[![Author](https://img.shields.io/badge/Author-Ishant_Sharma-blue.svg)](https://github.com/Kratos1996)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

![Mobile Security Architecture Banner](Ishant%20Sharma%20Mobile%20Security%20Handoff.png)

A Kotlin Multiplatform security foundation for Compose Multiplatform and native Android/iOS applications.

**Package:** `com.ishant.security`  
**Modules:**  
- `:security` — Core KMP library (cryptography, key abstractions, hardware identity, serialization helpers, handshake, and tests). Contains all crypto and keystore implementations (`AndroidDeviceIdentityKeyStore`, `IosDeviceIdentityKeyStore`, and `JvmDeviceIdentityKeyStore`).  
- `:app` — Unified Compose Multiplatform application sharing the exact same Compose UI (`commonMain/App.kt`) across Android, Desktop, and iOS.  
- `iosApp` — Xcode iOS project wrapping the shared Compose Multiplatform UI (`ComposeApp.framework`) inside a standard `ComposeUIViewController`.  
**Cipher:** AES-256-GCM  
**Handshake:** Ephemeral X25519 + HKDF-SHA256 + Ed25519 Transcript Signatures  
**Device Identity:** Android Keystore (Android), Secure Enclave (iOS) & Standard JCE KeyStore (JVM/Desktop) P-256 ECDSA  

## Status

Security foundation with AES-256-GCM encryption and an authenticated ephemeral X25519 + HKDF-SHA256 handshake protocol. This repository is structured as a Kotlin Multiplatform library with a unified Compose Multiplatform sample application running on Android, Desktop, and iOS.

## Installation

### Option 1: Maven Central (Recommended)
Add the dependency to your project's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.github.kratos1996:kmp-security:1.0.2")
}
```

### Option 2: JitPack

1. Add the JitPack repository in your root `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

2. Add the dependency:

```kotlin
dependencies {
    implementation("com.github.Kratos1996:KMP_Security:1.0.2")
}
```

## Project Architecture

```
KMP_Security/
├── security/                # Core KMP Security Library (All crypto and keystore logic)
│   ├── src/commonMain/      # AES-256-GCM, SecurityManager, Handshake, Session, Models
│   ├── src/androidMain/     # AndroidDeviceIdentityKeyStore (Android Keystore P-256 ECDSA)
│   ├── src/iosMain/         # IosDeviceIdentityKeyStore (Secure Enclave P-256 ECDSA)
│   ├── src/jvmMain/         # JvmDeviceIdentityKeyStore (JCA ECDSA P-256 file/memory keystore)
│   ├── src/commonTest/      # Cross-platform unit tests
│   └── src/jvmTest/         # JVM Keystore & crypto test suite
├── app/                     # Unified Compose Multiplatform Sample Application
│   ├── src/commonMain/      # Shared Compose UI (App.kt with Tabs: Encrypt/Decrypt & Automated Demos)
│   ├── src/androidMain/     # Android entry point (MainActivity.kt)
│   ├── src/desktopMain/     # Desktop entry point (Main.kt)
│   └── src/iosMain/         # iOS entry point (MainViewController.kt -> ComposeUIViewController)
└── iosApp/                  # Xcode iOS Shell
    ├── iosApp/              # Hosts ComposeView (ContentView.swift -> MainViewController())
    └── iosApp.xcodeproj     # Xcode project embedding ComposeApp.framework
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

## Unified Sample Application (`:app`)

The `:app` module provides a single, unified Compose Multiplatform UI (`app/src/commonMain/kotlin/com/ishant/security/sample/App.kt`) that runs natively on **Android**, **Desktop (JVM)**, and **iOS**:

- **Tab 1 — Encrypt / Decrypt Workbench:** Live, interactive payload encryption and decryption with optional Associated Authenticated Data (AAD) and one-click clipboard copying.
- **Tab 2 — Automated Security Checks:** One-click execution of automated checks verifying AES-256-GCM roundtrips, authentication tag tampering rejection, JSON payload parsing, ephemeral X25519 authenticated handshakes with Ed25519 transcript signing, and platform-specific Device Identity KeyStore (Android Keystore, Secure Enclave, or JVM KeyStore).

### Running on Android

```bash
./gradlew :app:assembleDebug
```

### Running on Desktop (JVM)

```bash
# Launch Compose Desktop window
./gradlew :app:desktopRun

# Or package standalone executable UberJar
./gradlew :app:packageUberJarForCurrentOS
```

### Running on iOS

The `iosApp` directory hosts a standard Xcode wrapper that displays the shared Compose Multiplatform UI through `ComposeUIViewController`:

```bash
# Build the Xcode project for iOS Simulator
xcodebuild -project iosApp/iosApp.xcodeproj -scheme iosApp -destination "platform=iOS Simulator,name=iPhone 18 Pro" build CODE_SIGNING_ALLOWED=NO

# Or open in Xcode:
open iosApp/iosApp.xcodeproj
```

## Build & Test Commands

Run unit tests across all platforms:

```bash
# Run JVM tests (including JvmDeviceIdentityKeyStore tests)
./gradlew :security:jvmTest

# Run Android unit tests
./gradlew :security:testDebugUnitTest

# Run iOS simulator native tests
./gradlew :security:iosSimulatorArm64Test
```

See [SECURITY.md](SECURITY.md), [SECURITY_PROTOCOL.md](SECURITY_PROTOCOL.md), and [CHANGELOG.md](CHANGELOG.md).

---

## Author & Maintainer

Created and maintained by **Ishant Sharma** ([@Kratos1996](https://github.com/Kratos1996)).
Email: `ishant.sharma1947@gmail.com`

