# FROST

Flexible round-optimized schnorr threshold signatures for Bitcoin.

## How to Use

The FROST protocol specifies two rounds for producing a threshold signature.

**Initial setup of parameters (using a trusted dealer):**

This repository uses a trusted dealer method for demonstration purposes. Feel free to use your own [Distributed Key Generation](https://en.wikipedia.org/wiki/Distributed_key_generation) (DKG) protocol for generating and distributing shares.

```ts
import { create_key_group } from '@cmdcode/frost/lib'
import { random_bytes }     from '@cmdcode/frost/util'

// Generate a random secret key and message.
const seckey  = random_bytes(32).hex
const message = random_bytes(32).hex

// Configure the paramaters of the group.
const secrets   = [ seckey ]
const threshold = 2
const share_max = 3

// Generate a group of secret shares.
const group = create_key_group(secrets, threshold, share_max)
```

**Round 1 Example (nonce commitments):**

Each member that is participating in the signing round must first create a nonce commitment:

```ts
import { create_commit_pkg } from '@cmdcode/frost/lib'

// Select a threshold (t) amount of shares and create nonce commitments.
const shares  = group.shares.slice(0, threshold)
const commits = shares.map(e => create_commit_pkg(e))
```

Each member then distributes their nonce commitment to other members.

**Round 2 Example (signing with secret shares):**

Once all participating member commitments have been collected, we can now produce a partial signature:

```ts
import {
  get_commit_pkg,
  get_session_context,
  sign_msg,
  verify_partial_sig
} from '@cmdcode/frost/lib'

// Compute the context data for the signing session.
const ctx = get_session_ctx(group.pubkey, commits, message)

// Convert the share indices into iterable numbers.
const idx = ctx.indexes.map(i => Number(i) - 1)

// Collect a partial signature from each share.
const psigs = idx.map(i => {
  const share  = shares[i]
  const commit = get_commit_pkg(commits, share)
  const sig    = sign_msg(ctx, share, commit)
  if (!verify_partial_sig(ctx, commit, sig.pubkey, sig.psig)) {
    throw new Error('sig share failed validation')
  }
  return sig
})
```

When the partial signatures have been collected, we can aggregate them into a full signature:

```ts
import { combine_partial_sigs, verify_final_sig } from '@cmdcode/frost/lib'

// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs(ctx, psigs)

// Check that the signature is valid.
const is_valid  = verify_final_sig(ctx, message, signature)

console.log('is valid:', is_valid)
```

## Development and Testing

To run the test suite, use the following commands:

```bash
yarn test    # For yarn.
npm run test # For NPM.
```

The test suite comes bundled with Bitcoin Core (located in `test/bin`) for testing purposes. Depending on your computer architecture, you may have to replace these binaries with another version, or change the default configuration in `test/tape.ts`.

There are code examples located in `test/examples` for performing various protocols via FROST and DKG. You can run a test file via the following command:

`yarn load test/example/<example_name>.ts`

Feel free to check them out!

## Resources

**ZF FROST Book**  
A guide to the FROST protocol.  
https://frost.zfnd.org/index.html  

**FROST draft specification**  
A draft specification of the FROST protocol from the IETF.  
https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html  

**ZCash FROST GitHub**  
A rust implementation of the IETF FROST draft spec, in rust.  
https://github.com/ZcashFoundation/frost  

**FROST BIP340**  
A draft implemenation of the FROST protocol for BIP340.  
https://github.com/jesseposner/FROST-BIP340  

**Draft BIP for Secure DKG**  
A draft proposal for secure DKG in FROST, provided by Blockstream Research.  
https://github.com/BlockstreamResearch/bip-frost-dkg  

**ROAST GitHub**  
A naive implementation of the ROAST protocol, written in rust.  
https://github.com/robot-dreams/roast  

**FROST Whitepaper**  
The white-paper for FROST: Flexible Round-Optimized Schnorr Threshold Signatures  
https://eprint.iacr.org/2020/852.pdf  

**ROAST Whitepaper**  
A white-paper for ROAST: Robust Asynchronous Schnorr Threshold Signatures.  
https://eprint.iacr.org/2022/550.pdf  
