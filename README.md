# FROST

Fast, round-optimized schnorr threshold signatures for Bitcoin.

## How to Use

The FROST protocol specifies two rounds for producing a threshold signature.

**Initial setup of parameters (using a trusted dealer):**

```ts
import { create_share_group } from '@cmdcode/frost/lib'
import { random_bytes }       from '@cmdcode/frost/util'

// Generate a random secret key and message.
const seckey  = random_bytes(32).hex
const message = random_bytes(32).hex

// Configure the paramaters of the group.
const secrets   = [ seckey ]
const threshold = 2
const share_max = 3

// Generate a group of secret shares.
const group = create_share_group(secrets, threshold, share_max)
```

**Round 1 Example (nonce commitments):**

```ts
import { create_commit_pkg } from '@cmdcode/frost/lib'

// Select a threshold (t) amount of shares and create nonce commitments.
const shares  = group.shares.slice(0, threshold)
const commits = shares.map(e => create_commit_pkg(e))
```

**Round 2 Example (signing with secret shares):**

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

Once a threshold (t) number of partial signatures have been collected, you can aggregate them into a full signature:

```ts
import { combine_partial_sigs, verify_final_sig } from '@cmdcode/frost/lib'

// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs(ctx, psigs)

// Check that the signature is valid.
const is_valid  = verify_final_sig(ctx, message, signature)

console.log('is valid:', is_valid)
```

The FROST protocol does not specify how the shamir secret is generated, or how the secret shares are distributed to the signers. This repository use a trusted dealer method for demonstration purposes. Feel free to use your own DKG protocol for generating and distributing shares.

## Development and Testing

To run the test suite, use the following commands:

```bash
yarn test    # For yarn.
npm run test # For NPM.
```

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
