# Security protocol v1

This repository contains client-side cryptographic primitives only. It performs no HTTP calls and never replaces TLS.

## Transport requirements

- Use HTTPS with TLS 1.3 for handshake and all application traffic.
- Never disable certificate validation.
- Authenticate the backend signing identity using a preconfigured/pinned public key or a reviewed certificate/key-rotation scheme.
- Never trust a signing key supplied only by the unauthenticated ServerHello.

## Handshake

1. Client generates a fresh ephemeral X25519 key pair and 32-byte random client nonce.
2. Client sends ClientHello containing protocol/suite identifiers, ephemeral public key in DER SubjectPublicKeyInfo format, and client nonce.
3. Backend generates a fresh ephemeral X25519 key pair, 32-byte server nonce, and unique session ID.
4. Backend signs the canonical transcript (see HandshakeTranscript.kt) with Ed25519 using its long-term signing key held in KMS/HSM. ServerHello declares signatureAlgorithm = Ed25519. The signature covers both ephemeral public keys, both nonces, protocol/suite identifiers, session ID, signing key ID and signature algorithm.
5. Client verifies the signature using its pre-trusted server signing key before accepting the server ephemeral key.
6. Both sides compute X25519(client ephemeral private key, server ephemeral public key).
7. Both derive independent 32-byte keys using HKDF-SHA256, salt = clientNonce || serverNonce, and info labels:
   - yralfood-security/v1/{sessionId}/client-to-server
   - yralfood-security/v1/{sessionId}/server-to-client
8. Never transmit private keys or the raw shared secret. Discard ephemeral private/shared-secret material as soon as practical.

## Message protection

- AES-256-GCM uses a fresh provider-generated nonce for every encryption.
- Requests and responses use independent keys.
- AAD is UTF-8: yralfood-security/v1|{sessionId}|{direction}|{sequence}
- Direction is c2s for client requests and s2c for server responses.
- Sequence starts at zero and increases by exactly one per direction. Reject duplicates, gaps and out-of-order messages.
- Re-handshake on expiry, logout, revocation, compromise, or sequence exhaustion.

## Backend interoperability

Backend must match X25519, DER/SPKI public-key encoding, HKDF-SHA256 parameters and labels, AES-GCM nonce/ciphertext/tag representation, AAD bytes, and sequence policy exactly. Add cross-language test vectors before production rollout.

## Explicit implementation boundary

ServerHandshakeVerifier is an injected trust boundary. The app must implement it using a pinned backend signing public key (or a reviewed certificate/key-rotation scheme). This library intentionally does not accept arbitrary server keys or embed production signing keys.

Android Keystore and iOS Keychain adapters for persistent device identity keys are not included in this ephemeral session API. They are separate platform-specific work.
