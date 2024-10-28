# FROST

Fast, round-optimized schnorr threshold signatures for Bitcoin.

## How to Use

The FROST protocol specifies two rounds for producing a threshold signature.

**Initial setup of parameters (using a trusted dealer):**

```ts
import { create_dealer_pkg } from '@cmdcode/frost/lib'

const secrets     = [ 'optional_secret_key' ]
const message     = new TextEncoder().encode('hello world!')
const threshold   = 11
const share_count = 15

// Generate a secret, package of shares, and group key.
const pkg = create_dealer_pkg(secrets, thold, share_ct)
```

**Round 1 Example (nonce commitments):**

```ts
import { create_commit_pkg } from '@cmdcode/frost/lib'

// Use a t amount of shares to create nonce commitments.
const commits = pkg.shares.slice(0, thold).map(e => {
  return create_commit_pkg(e)
})
```

**Round 2 Example (signing with secret shares):**

```ts
import { get_context, sign } from '@cmdcode/frost/lib'

// Compute some context data for the signing session.
const context = get_session_context (
  commits, pkg.group_pubkey, message
)
// Create the partial signatures for a given signing context.
const psigs = members.map((_, i) => {
  return sign_msg(context, pkg.shares[i], commits[i])
})
```

Once a threshold (t) number of shares have been collected, you can aggregate them into a single signature:

```ts
import { combine_partial_sigs, verify_final_sig } from '@cmdcode/frost/lib'

// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs (
  commits, message, pkg.group_pubkey, psigs
)
// Check that the signature is valid
const is_valid = verify_final_sig(context, signature)

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
