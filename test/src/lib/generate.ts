import { Buff } from '@cmdcode/buff'

import { get_record, random_bytes } from '@cmdcode/frost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_share_group,
  get_commit_pkg,
  get_session_ctx,
  sign_msg,
  verify_final_sig,
  verify_share
} from '@cmdcode/frost/lib'

const secrets  = [ random_bytes(32), random_bytes(32) ]
const message  = random_bytes(32).hex
const thold    = 2
const share_ct = 3
const nseed_h = secrets[0].hex
const nseed_b = secrets[1].hex

// Generate a group of shares that represent a public key.
const group = create_share_group(secrets, thold, share_ct)

// Verify that all shares are included in the group key.
const is_valid_shares = group.shares.every(e => {
  if (!verify_share(group.commits, e, thold)) {
    throw new Error('invalid share in the group at index: ' + e.idx)
  }
})

// 
if (!is_valid_shares) throw new Error('shares failed validation')
// Use a t amount of shares to create nonce commitments.
const shares  = group.shares.slice(0, thold)
const commits = shares.map(e => create_commit_pkg(e, nseed_h, nseed_b))
// Compute some context data for the signing session.
const ctx = get_session_ctx(group.pubkey, commits, message)
const idx = ctx.indexes.map(i => Number(i) - 1)
// Create the partial signatures for a given signing context.
const psigs = idx.map(i => {
  const share  = shares[i]
  const commit = get_commit_pkg(commits, share)
  return sign_msg(ctx, share, commit)
})
// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs(ctx, psigs)
const is_valid  = verify_final_sig(ctx, message, signature)

console.log(JSON.stringify({
  "group": {
    "share_min"    : 2,
    "share_max"    : 3,
    "indexes"      : ctx.indexes.map(e => Number(e)),
    "challenge"    : Buff.big(ctx.challenge, 32).hex,
    "commits"      : group.commits,
    "message"      : Buff.bytes(message).hex,
    "grp_pnonce"   : ctx.group_pn,
    "grp_pubkey"   : ctx.group_pk,
    "grp_prefix"   : ctx.bind_prefix,
    "secrets"      : secrets,
    "sig"          : signature
  },
  "members" : idx.map(i => {
    const share  = shares[i]
    const commit = get_commit_pkg(commits, share)
    const psig   = get_record(psigs, i).psig
    const binder = get_record(ctx.bind_factors, i).bind_hash
    return { ...commit, ...share, nseed_h, nseed_b, binder, psig }
  })
}, null, 2))

console.log('is valid:', is_valid)
