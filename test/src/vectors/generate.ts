import { Buff }                                      from '@cmdcode/buff'
import { get_full_context }                          from '@bifrost/context'
import { get_record, random_bytes }                  from '@bifrost/util'
import { sign_msg, verify_sig }                      from '@bifrost/sign'
import { combine_sig_shares, create_commitment }     from '@/proto.js'
import { create_share_package, verify_share_commit } from '@/shares.js'

const secrets  = [ random_bytes(32), random_bytes(32) ]
const message  = new TextEncoder().encode('hello world!')
const thold    = 2
const share_ct = 3
const nseed_h = secrets[0].hex
const nseed_b = secrets[1].hex

// Generate a secret, package of shares, and group key.
const { vss_commits, group_pubkey, sec_shares } = create_share_package(secrets, thold, share_ct)
//
const is_valid_shares = sec_shares.every(e => verify_share_commit(vss_commits, e, thold))
//
if (!is_valid_shares) throw new Error('shares failed validation')
// Use a t amount of shares to create nonce commitments.
const members     = sec_shares.slice(0, thold).map(e => create_commitment(e, nseed_h, nseed_b))
// Collect the commitments into an array.
const sec_nonces  = members.map(mbr => mbr.sec_nonces)
const pub_nonces  = members.map(mbr => mbr.pub_nonces)
// Compute some context data for the signing session.
const context     = get_full_context(group_pubkey, pub_nonces, message)
// Create the partial signatures for a given signing context.
const psigs = context.identifiers.map(idx => {
  const sec_share = get_record(sec_shares, Number(idx))
  const sec_nonce = get_record(sec_nonces, Number(idx))
  return sign_msg(context, sec_share, sec_nonce)
})
// Aggregate the partial signatures into a single signature.
const signature = combine_sig_shares(context, psigs)
const is_valid  = verify_sig(context, message, signature)

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
    const idx                    = Number(i)
    const { seckey }             = get_record(sec_shares, idx)
    const { snonce_h, snonce_b } = get_record(sec_nonces, idx)
    const { pnonce_h, pnonce_b } = get_record(pub_nonces, idx)
    const psig    = get_record(psigs, idx).sig
    const binder  = get_record(context.bind_factors, idx).key
    return { idx, seckey, nseed_h, nseed_b, snonce_h, snonce_b, pnonce_h, pnonce_b, binder, psig }
  })
}, null, 2))

console.log('is valid:', is_valid)
