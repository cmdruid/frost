# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4]

### Added

#### Input Validation
- `create_share_set()`: Added validation that `share_max >= 1`
- `create_share_set()`: Added validation that `threshold <= share_max`
- `create_share_coeffs()`: Added validation that `threshold >= 1`
- `create_ecdh_share()`: Added validation that `share.idx` is present in `members` array
- `create_shares()`: Added validation that `coeffs` array is non-empty

#### Domain Separation Constants
- Added `DST` constant object in `src/const.ts` with named constants for FROST hash function domain separation tags:
  - `DST.RHO` - binding factor computation
  - `DST.CHAL` - Schnorr challenge
  - `DST.NONCE` - nonce derivation
  - `DST.MSG` - message pre-hashing
  - `DST.COM` - commitment encoding

#### Documentation
- Added comprehensive JSDoc documentation to all public functions across:
  - `src/lib/commit.ts` - commitment operations
  - `src/lib/ecdh.ts` - threshold ECDH
  - `src/lib/group.ts` - key group generation
  - `src/lib/helpers.ts` - utility functions
  - `src/lib/shares.ts` - secret share management
  - `src/lib/sign.ts` - signing operations
  - `src/lib/vss.ts` - verifiable secret sharing
  - `src/ecc/hash.ts` - domain-separated hash functions
- Added `@fileoverview` headers to all source files
- Added `@security` annotations for security-critical operations
- Expanded JSDoc for `get_group_prefix()` with parameter and return descriptions
- Expanded JSDoc for `tweak_pubkey()` explaining its relationship to `tweak_seckey()`
- Added clarifying note to `CommitmentPackage` type explaining the intersection semantics
- Added comprehensive documentation to type definitions in `src/types/`

### Changed

#### Code Quality Improvements
- **sign.ts**: Improved variable naming for clarity:
  - `Q` → `group_pt` (group point context)
  - `snonce_h` → `hidden_nonce`
  - `snonce_b` → `binder_nonce`
  - `sk` → `adjusted_secret`
  - `nk` → `combined_nonce`
  - `ps` → `partial_sig`

- **hash.ts**: Refactored to use `DST.*` constants instead of hardcoded string literals

- **helpers.ts**: Extracted `BIP340_CHALLENGE_TAG` constant for the BIP340 challenge domain

- **commit.ts**: Changed array building pattern from spread reassignment to `push()` for better performance:
  ```typescript
  // Before
  enc_group_commit = [ ...enc_group_commit, ...enc_commit ]
  // After
  enc_group_commit.push(...enc_commit)
  ```

- **assert.ts**: Standardized error handling:
  - Changed `TypeError` to `Error` for consistency
  - Normalized error messages to lowercase without exclamation marks:
    - `'Assertion failed!'` → `'assertion failed'`
    - `'Input is undefined!'` → `'input is undefined'`
    - `'Input is null!'` → `'input is null'`
  - Optimized `is_unique_set()` to use `Set` instead of `filter()` for O(n) instead of O(n²) complexity

### Fixed

- **types/sign.ts**: Removed inconsistent trailing comma in `ShareSignature` interface
- **assert.ts**: Fixed typo `array_b. length` → `array_b.length`
- **ecdh.ts**: Simplified `derive_ecdh_secret()` by using `G.ElementAdd()` consistently

### Security

- All input validation additions help prevent undefined behavior from invalid parameters
- Added `@security` JSDoc annotations to document critical security requirements:
  - Nonce reuse prevention in `sign_msg()`, `generate_nonce()`, `create_commit_pkg()`
  - Secret nonce confidentiality warnings in `SecretNonce` type
  - Trusted dealer model warning in `create_dealer_set()`

## [1.1.3] - Previous Release

See git history for changes prior to this changelog.
