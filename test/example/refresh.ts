import { random_bytes } from '@cmdcode/frost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_dealer_set,
  gen_refresh_shares,
  get_commit_pkg,
  get_group_signing_ctx,
  get_pubkey,
  get_share,
  refresh_share,
  sign_msg,
  verify_final_sig,
  verify_partial_sig
} from '@cmdcode/frost/lib'

import { collect_shares } from '../src/lib/util.js'

const message = random_bytes(32).hex
const seckey  = random_bytes(32).hex
const pubkey  = get_pubkey(seckey)

console.log('master pk:', pubkey)

const secrets  = [ seckey ]
const share_ct = 3
const thold    = 2

// Generate a secret, package of shares, and group key.
const group = create_dealer_set(thold, share_ct, secrets)

console.log('group pk:', group.group_pk)

// Distribute the shares.
const share_1 = get_share(group.shares, 1)
const share_2 = get_share(group.shares, 2)
const share_3 = get_share(group.shares, 3)

// Generate refresh shares from each member.
const ref_shares_1 = gen_refresh_shares(1, thold, share_ct).shares
const ref_shares_2 = gen_refresh_shares(2, thold, share_ct).shares
const ref_shares_3 = gen_refresh_shares(3, thold, share_ct).shares
const ref_shares_g = [ ref_shares_1, ref_shares_2, ref_shares_3 ]

// Collect the refresh shares from each member.
const agg_shares_1 = collect_shares(ref_shares_g, 1)
const agg_shares_2 = collect_shares(ref_shares_g, 2)
const agg_shares_3 = collect_shares(ref_shares_g, 3)

// Update the existing share to the new share.
const new_share_1 = refresh_share(agg_shares_1, share_1)
const new_share_2 = refresh_share(agg_shares_2, share_2)
const new_share_3 = refresh_share(agg_shares_3, share_3)
const new_shares  = [ new_share_1, new_share_2, new_share_3 ]

// Select a threshold (t) amount of shares and create nonce commitments.
const commits = new_shares.map(e => create_commit_pkg(e))

// Compute the context data for the signing session.
const ctx = get_group_signing_ctx(group.group_pk, commits, message)

// Convert the share indices into iterable numbers.
const idx = ctx.indexes.map(i => Number(i) - 1)

// Collect a partial signature from each share.
const psigs = idx.map(i => {
  const share  = new_shares[i]
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
