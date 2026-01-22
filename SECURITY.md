# Security Considerations

This document outlines security considerations for using this FROST implementation.

## JavaScript Runtime Limitations

### Memory Management

JavaScript does not provide direct memory management. This means:

- **BigInts cannot be reliably zeroed**: Secret values stored as bigints remain in memory until garbage collected. There is no way to explicitly clear them.
- **Strings are immutable**: Hex-encoded secrets (like `seckey` fields) cannot be overwritten in place.
- **No secure memory allocation**: Unlike native implementations, JavaScript cannot use `mlock()` or similar to prevent secrets from being swapped to disk.

### Timing Considerations

This implementation is **not constant-time**:

- Scalar operations may have data-dependent timing
- Point operations from `@noble/curves` aim for constant-time but run in JavaScript
- Conditional branches based on secret data may leak information via timing

## Appropriate Use Cases

This implementation is suitable for:

- **Online signing operations** where signers are connected and coordinating
- **Development and testing** of FROST-based protocols
- **Educational purposes** to understand threshold signatures
- **Prototype applications** where security requirements allow JavaScript

## Inappropriate Use Cases

This implementation should **NOT** be used for:

- **Cold storage** of high-value keys
- **HSM replacement** in security-critical applications
- **Air-gapped signing** where constant-time guarantees are required
- **Long-term key storage** on untrusted systems

For these use cases, consider native implementations with proper memory protection.

## Critical Security Requirements

### Nonce Reuse Prevention

**CRITICAL**: Nonce reuse enables extraction of the secret share.

- Each `SecretNonce` (containing `hidden_sn` and `binder_sn`) MUST be used for exactly one signature
- Never reuse nonces across different signing sessions
- If using deterministic nonce generation, ensure the aux seed is unique per session
- After calling `sign_msg()`, the nonce should be discarded

### Commitment Verification

Before aggregating partial signatures:

- Verify each participant's commitment matches their public nonce
- Use `verify_partial_sig()` to validate each partial signature
- Only aggregate signatures from verified, trusted participants

### Share Verification

When receiving shares (in DKG or trusted dealer mode):

- Always verify shares against VSS commitments using `verify_share()`
- Reject shares that fail verification
- Do not use unverified shares for signing

## Serialization Warnings

### SecretShare

The `SecretShare` type contains:
```typescript
{
  idx: number,    // Public: participant index
  seckey: string  // SECRET: 32-byte hex scalar
}
```

**Warning**: Serializing or logging `SecretShare` objects exposes the secret key. Never:
- Log share objects
- Store shares in plaintext
- Transmit shares over unencrypted channels
- Include shares in error messages

### SecretNonce

The `SecretNonce` type contains:
```typescript
{
  idx: number,       // Public: participant index
  hidden_sn: string, // SECRET: hiding nonce
  binder_sn: string  // SECRET: binding nonce
}
```

**Warning**: These are one-time secrets. Exposure enables signature forgery. Never:
- Log nonce objects
- Store nonces persistently
- Transmit nonces to other parties
- Reuse nonces across signing sessions

### CommitmentPackage

The `CommitmentPackage` combines both secret and public nonces. When sharing commitments:
- Only share the `PublicNonce` portion (`hidden_pn`, `binder_pn`)
- Keep the secret portion (`hidden_sn`, `binder_sn`) private

## Reporting Security Issues

If you discover a security vulnerability in this implementation, please report it responsibly by opening a private security advisory on the GitHub repository.
