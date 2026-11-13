# Security checklist

- [ ] Define authenticated key provisioning and rotation with the backend.
- [ ] Implement Android Keystore-backed cipher adapter (non-exportable key support).
- [ ] Implement Apple Keychain/CryptoKit-backed cipher adapter.
- [ ] Agree exact envelope encoding and AAD rules with the backend.
- [ ] Add cross-platform known-answer tests and backend interoperability tests.
- [ ] Review key lifecycle, backup/restore, device migration and account logout behavior.
- [ ] Run dependency and static security scans before release.

## Rules

1. Never hardcode or commit production keys.
2. Never log plaintext, keys, nonces together with sensitive metadata, or decrypted API bodies.
3. Never reuse a GCM nonce with the same key. Use the provider's random-IV encryption API.
4. Treat any GCM authentication error as a hard failure; never return partial plaintext.
5. Bind ciphertext to its intended context using AAD where protocol design permits.
6. Use TLS, authentication, authorization, rate limits and replay defenses independently.
7. Do not claim Keystore/Keychain protection until the platform adapter is implemented and tested.
