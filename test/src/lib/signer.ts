import { random_bytes } from '@cmdcode/frost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_dealer_set,
  get_commit_pkg,
  get_group_signing_ctx,
  sign_msg,
  verify_final_sig,
  verify_partial_sig,
  verify_share
} from '@cmdcode/frost/lib'

import type { DealerShareSet } from '@/types/index.js'

export function frost_keygen (
  threshold  : number = 11,
  max_shares : number = 15
) {
  //
  const secrets = [ random_bytes(32) ]
  // Generate a secret, package of shares, and group key.
  const group = create_dealer_set(threshold, max_shares, secrets)
  //
  group.shares.forEach(e => {
    if (!verify_share(group.vss_commits, e, threshold)) {
      throw new Error(`share ${e.idx} failed validation:, ${e.seckey}`)
    }
  })
  //
  return group
}

export function frost_sign (
  group   : DealerShareSet,
  message : string,
  tweaks  : string[] = [],
) {
  // Use a t amount of shares to create nonce commitments.
  const threshold = group.vss_commits.length
  const shares    = group.shares.slice(0, threshold)
  const commits   = shares.map(e => create_commit_pkg(e))
  // Compute some context data for the signing session.
  const ctx = get_group_signing_ctx(group.group_pk, commits, message, tweaks)
  const idx = ctx.indexes.map(i => Number(i) - 1)
  // Create the partial signatures for a given signing context.
  const psigs = idx.map(i => {
    const share  = shares[i]
    const commit = get_commit_pkg(commits, share)
    const sig    = sign_msg(ctx, share, commit)
    if (!verify_partial_sig(ctx, commit, sig.pubkey, sig.psig)) {
      console.log(`psig ${idx}:, ${sig.psig}`)
      throw new Error('sig share failed validation')
    }
    return sig
  })

  // Aggregate the partial signatures into a single signature.
  const signature = combine_partial_sigs(ctx, psigs)
  const is_valid  = verify_final_sig(ctx, message, signature)

  if (!is_valid) {
    throw new Error('final signature failed validation')
  }

  return signature
}
