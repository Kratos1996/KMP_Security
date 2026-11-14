# Security protocol v1

This repository contains client-side cryptographic primitives only. It performs no HTTP calls and never replaces TLS.

## Transport requirements

- Use HTTPS with TLS 1.3 for handshake and all application traffic.
- Never disable certificate validation.
- Authenticate the backend signing identity using a preconfigured/pinned public key or a reviewed certificate/key-rotation scheme.
- Never trust a signing key supplied only by the unauthenticated ServerHello.

## Persistent device identity

- The app creates one installation identity key through the `DeviceIdentityKeyStore` adapter.
- The key is ECDSA P-256 with SHA-256 signatures; public key encoding is DER SubjectPublicKeyInfo.
- The private key must be generated and retained by Android Keystore or an appropriate iOS Keychain/Secure Enclave-backed implementation. It must never be exported to common Kotlin code or sent to the backend.
- Register the public key and key ID with the backend. For proof of possession, the backend issues a fresh, unpredictable, single-use challenge over TLS; the app signs the exact challenge and returns the signature.
- Backend verifies the challenge signature against the registered public key, enforces expiry/single use, and binds the identity to the authenticated account/device record.
- Logout does not automatically delete the installation identity. Delete it only during explicit device de-registration, app reset, or a reviewed key-rotation flow.
- Android implementation is provided by `AndroidDeviceIdentityKeyStore` in `androidMain` and uses Android Keystore with a P-256 signing key. iOS implementation is provided by `IosDeviceIdentityKeyStore` in `iosMain` and requires Secure Enclave; it intentionally fails closed on simulators/devices where Secure Enclave key generation is unavailable. Neither implementation exports the private key. Backend challenge endpoints remain integration work.

## Handshake

1. Client generates a fresh ephemeral X25519 key pair and 32-byte random client nonce.
2. Client sends ClientHello containing protocol/suite identifiers, ephemeral public key in DER SubjectPublicKeyInfo format, and client nonce.
3. Backend generates a fresh ephemeral X25519 key pair, 32-byte server nonce, and unique session ID.
4. Backend signs the canonical transcript (see HandshakeTranscript.kt) with Ed25519 using its long-term signing key held in KMS/HSM. ServerHello declares signatureAlgorithm = Ed25519. The signature covers both ephemeral public keys, both nonces, protocol/suite identifiers, session ID, signing key ID and signature algorithm.
5. Client verifies the signature using its pre-trusted server signing key before accepting the server ephemeral key.
6. Both sides compute X25519(client ephemeral private key, server ephemeral public key).
7. Both derive independent 32-byte keys using HKDF-SHA256, salt = clientNonce || serverNonce, and info labels:
   - kmp-security/v1/{sessionId}/client-to-server
   - kmp-security/v1/{sessionId}/server-to-client
8. Never transmit private keys or the raw shared secret. Discard ephemeral private/shared-secret material as soon as practical.

## Message protection

- AES-256-GCM uses a fresh provider-generated nonce for every encryption.
- Requests and responses use independent keys.
- AAD is UTF-8: kmp-security/v1|{sessionId}|{direction}|{sequence}
- Direction is c2s for client requests and s2c for server responses.
- Sequence starts at zero and increases by exactly one per direction. Reject duplicates, gaps and out-of-order messages.
- Re-handshake on expiry, logout, revocation, compromise, or sequence exhaustion.

## Backend interoperability

Backend must match X25519, DER/SPKI public-key encoding, HKDF-SHA256 parameters and labels, AES-GCM nonce/ciphertext/tag representation, AAD bytes, and sequence policy exactly. Add cross-language test vectors before production rollout.

## Explicit implementation boundary

ServerHandshakeVerifier is an injected trust boundary. The app must implement it using a pinned backend signing public key (or a reviewed certificate/key-rotation scheme). This library intentionally does not accept arbitrary server keys or embed production signing keys.

The common module exposes the persistent identity contract in DeviceIdentity.kt. `PinnedEd25519HandshakeVerifier` verifies transcript signatures only against an application-provisioned allow-list of DER/SPKI Ed25519 public keys. Key rotation must be delivered through an authenticated application configuration/release channel. Backend registration/challenge endpoints and production key provisioning remain integration work.
