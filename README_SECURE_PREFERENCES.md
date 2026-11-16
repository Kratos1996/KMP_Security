# Secure Preferences for KMP_Security

This branch adds a secure key/value persistence layer to the existing KMP security foundation.

## Design
- Reuses the existing AES-256-GCM implementation and versioned EncryptedPayload.
- Does not reuse the P-256 device identity signing key for encryption.
- Separates key management from persistence.
- Persists only serialized, encrypted payloads. Keys are supplied by a dedicated platform key provider and are never stored beside ciphertext.
- Uses suspend APIs so browser WebCrypto and platform key stores do not block UI threads.

## Target status
The repository currently configures Android, JVM and iOS targets. JavaScript and WebAssembly targets must be added with platform-specific adapters before claiming Web support. This branch establishes the common preferences contracts; it does not yet claim complete platform support.

## Public API direction
The intended consumer experience is:
```kotlin
val preferences = SecurePreferences.create(
    name = "account",
    keyProvider = platformKeyProvider,
    store = platformEncryptedStore
)

preferences.putString("access_token", token)
val saved = preferences.getString("access_token")
preferences.remove("access_token")
```

All I/O operations are suspending. The familiar SharedPreferences-style names are retained while avoiding blocking calls.

## Security boundaries
- AES-GCM requires a unique 96-bit nonce per encryption key. The existing provider creates a fresh nonce.
- Associated data binds each encrypted value to its storage namespace, key, and format version.
- Authentication failures are surfaced as errors; they must not be converted into default values.
- A platform key provider must return a key handle usable by its crypto implementation. A raw exported key is not an acceptable adapter for non-exportable Android Keystore or WebCrypto keys.
- Web encryption cannot protect against malicious JavaScript executing in the same origin (for example, XSS).
- Desktop production support requires OS credential storage (Keychain, Credential Manager/DPAPI, Secret Service/libsecret). A plaintext key file is not acceptable.

## Next implementation steps
1. Add a crypto abstraction that supports opaque platform key handles as well as the existing RawAesKey.
2. Implement Android AES key generation/use inside Android Keystore.
3. Implement iOS persistent AES key handling using Keychain-protected key material and CryptoKit.
4. Implement desktop OS credential store adapters for macOS, Windows and Linux.
5. Implement browser WebCrypto non-extractable keys persisted in IndexedDB, with atomic encrypted record writes.
6. Add JS and Wasm targets and run CI on all supported targets.
7. Add key rotation, recovery/migration policy, concurrency tests and platform integration tests.
