import { Buff } from '@cmdcode/buff'

import { get_record, random_bytes } from '@bifrost/util'

import {
  combine_partial_sigs,
  create_nonce_pkg,
  create_share_pkg,
  get_session_ctx,
  sign_msg,
  verify_final_sig,
  verify_share_membership
} from '@bifrost/lib'

const secrets  = [ random_bytes(32), random_bytes(32) ]
const message  = new TextEncoder().encode('hello world!')
const thold    = 2
const share_ct = 3
const nseed_h = secrets[0].hex
const nseed_b = secrets[1].hex

// Generate a secret, package of shares, and group key.
const { vss_commits, group_pubkey, sec_shares } = create_share_pkg(secrets, thold, share_ct)
// 
const is_valid_shares = sec_shares.every(e => verify_share_membership(vss_commits, e, thold))
// 
if (!is_valid_shares) throw new Error('shares failed validation')
// Use a t amount of shares to create nonce commitments.
const members     = sec_shares.slice(0, thold)
const commits     = members.map(e => create_nonce_pkg(e, nseed_h, nseed_b))
// Collect the commitments into an array.
const sec_nonces  = commits.map(mbr => mbr.secnonce)
const pub_nonces  = commits.map(mbr => mbr.pubnonce)
// Compute some context data for the signing session.
const context     = get_session_ctx(group_pubkey, pub_nonces, message)
// Create the partial signatures for a given signing context.
const psigs = context.identifiers.map(idx => {
  const sec_share = get_record(sec_shares, Number(idx))
  const sec_nonce = get_record(sec_nonces, Number(idx))
  return sign_msg(context, sec_share, sec_nonce)
})
// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs(context, psigs)
const is_valid  = verify_final_sig(context, message, signature)

console.log(JSON.stringify({
  "group": {
    "share_min"    : 2,
    "share_max"    : 3,
    "identifiers"  : context.identifiers.map(e => Number(e)),
    "challenge"    : Buff.big(context.challenge, 32).hex,
    "commits"      : vss_commits,
    "message"      : Buff.bytes(message).hex,
    "grp_pnonce"   : context.group_pnonce,
    "grp_pubkey"   : context.group_pubkey,
    "grp_prefix"   : context.bind_prefix,
    "secrets"      : secrets,
    "sig"          : signature
  },
  "members" : context.identifiers.map(i => {
    const idx = Number(i)
    const { seckey }               = get_record(sec_shares, idx)
    const { binder_sn, hidden_sn } = get_record(sec_nonces, idx)
    const { binder_pn, hidden_pn } = get_record(pub_nonces, idx)
    const psig   = get_record(psigs, idx).psig
    const binder = get_record(context.bind_factors, idx).key
    return { idx, seckey, nseed_h, nseed_b, binder_sn, binder_pn, hidden_sn, hidden_pn, binder, psig }
  })
}, null, 2))

console.log('is valid:', is_valid)
