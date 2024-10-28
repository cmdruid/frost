import { get_record, random_bytes } from '@cmdcode/frost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_share_pkg,
  get_pubkey,
  get_session_ctx,
  sign_msg,
  verify_final_sig,
  verify_partial_sig
} from '@cmdcode/frost/lib'

const seckey  = random_bytes(32).hex
const message = random_bytes(32).hex

const secrets  = [ seckey ]
const share_ct = 3
const thold    = 2

// Generate a secret, package of shares, and group key.
const { group_pubkey, sec_shares } = create_share_pkg(secrets, thold, share_ct)

// Use a t amount of shares to create nonce commitments.
const commits = sec_shares.slice(0, thold).map(e => create_commit_pkg(e))

// Collect the commitments into an array.
const sec_nonces = commits.map(mbr => mbr.secnonce)
const pub_nonces = commits.map(mbr => mbr.pubnonce)

// Compute some context data for the signing session.
const context = get_session_ctx(group_pubkey, pub_nonces, message)

// Create the partial signatures for a given signing context.
const psigs = context.identifiers.map(i => {
  const idx = Number(i)
  const sec_share = get_record(sec_shares, idx)
  const sec_nonce = get_record(sec_nonces, idx)
  const pub_nonce = get_record(pub_nonces, idx)
  const sig_share = sign_msg(context, sec_share, sec_nonce)
  const share_pk  = get_pubkey(sec_share.seckey)
  if (!verify_partial_sig(context, pub_nonce, share_pk, sig_share.psig)) {
    throw new Error('sig share failed validation')
  }
  return sig_share
})

// Aggregate the partial signatures into a single signature.
const signature = combine_partial_sigs(context, psigs)
const is_valid  = verify_final_sig(context, message, signature)

console.log('is valid:', is_valid)
