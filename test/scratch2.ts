import { random_bytes } from '@cmdcode/frost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_share_group,
  get_commit_pkg,
  get_session_ctx,
  sign_msg,
  verify_final_sig,
  verify_partial_sig
} from '@cmdcode/frost/lib'

const seckey  = random_bytes(32).hex
const message = random_bytes(32).hex

const secrets   = [ seckey ]
const threshold = 2
const share_max = 3

// Generate a group of secret shares.
const group = create_share_group(secrets, threshold, share_max)

// Select a threshold (t) amount of shares and create nonce commitments.
const shares  = group.shares.slice(0, threshold)
const commits = shares.map(e => create_commit_pkg(e))

// Compute the context data for the signing session.
const ctx = get_session_ctx(group.pubkey, commits, message)

// Convert the context indices into iterable numbers.
const idx = ctx.indexes.map(i => Number(i))

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

// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs(ctx, psigs)
const is_valid  = verify_final_sig(ctx, message, signature)

console.log('is valid:', is_valid)
