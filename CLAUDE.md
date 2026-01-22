# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is a TypeScript implementation of threshold signatures for Bitcoin. It enables a threshold of participants to collaboratively produce valid Schnorr signatures without any single party having access to the complete secret key.

## Common Commands

```bash
npm run test      # Run the full test suite with Tape
npm run build     # Build the project (TypeScript + Rollup)
npm run release   # Run tests then build
npm run scratch   # Run scratch test file (test/scratch.ts)

# Run a specific test or example file
npm run load test/example/<example_name>.ts
```

## Architecture

The codebase is organized into three main modules, each with a separate export path:

- **`@cmdcode/frost/lib`** - Core FROST protocol implementation (signing, commitments, shares, VSS)
- **`@cmdcode/frost/ecc`** - Elliptic curve operations (secp256k1 group ops, hashing, point state management)
- **`@cmdcode/frost/util`** - Utility functions (assertions, helpers, random bytes)

### Source Structure

```
src/
├── lib/           # Core protocol: signing, commitments, shares, VSS, key groups
├── ecc/           # EC operations: group math, hashing (H1-H5), point state
├── util/          # Assertions, helpers
└── types/         # TypeScript type definitions
```

### FROST Protocol Flow

1. **Setup** - `create_key_group()` generates secret shares and group pubkey (trusted dealer or DKG)
2. **Round 1** - Each participant calls `create_commit_pkg()` to create nonce commitments
3. **Round 2** - `get_session_ctx()` computes signing context, then `sign_msg()` creates partial signatures
4. **Aggregation** - `combine_partial_sigs()` produces the final signature
5. **Verification** - `verify_final_sig()` validates using BIP340 Schnorr

## TypeScript Configuration

- Uses path alias `@/*` → `src/*` for imports
- Strict mode enabled with all strict checks (noImplicitAny, strictNullChecks, noUnusedLocals, etc.)
- Target: ESNext, Module: NodeNext

## Testing

- **Framework**: Tape with Faucet for output formatting
- **Bitcoin integration**: Uses Bitcoin Core binaries in `test/bin/` for regtest testing
- **Test vectors**: Located in `test/src/vectors/spec.json`
- **Examples**: `test/example/` contains various protocol demonstrations

## Key Dependencies

- `@noble/curves` - secp256k1 curve implementation
- `@noble/hashes` - Cryptographic hash functions
- `@vbyte/buff` - Buffer manipulation utilities
