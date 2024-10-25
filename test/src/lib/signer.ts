import { get_record, random_bytes } from '@bifrost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_share_pkg,
  get_pubkey,
  get_session_ctx,
  sign_msg,
  verify_final_sig,
  verify_partial_sig,
  verify_share_membership
} from '@bifrost/lib'

import type { SharePackage } from '@/types/index.js'

export function frost_keygen (
  threshold  : number = 11,
  max_shares : number = 15
) {
  //
  const secrets = [ random_bytes(32) ]
  // Generate a secret, package of shares, and group key.
  const pkg = create_share_pkg(secrets, threshold, max_shares)
  //
  pkg.sec_shares.forEach(e => {
    if (!verify_share_membership(pkg.vss_commits, e, threshold)) {
      throw new Error(`share ${e.idx} failed validation:, ${e.seckey}`)
    }
  })
  //
  return pkg
}

export function frost_sign (
  pkg        : SharePackage,
  message    : string,
  tweaks     : string[] = [],
  threshold  : number   = 11,
) {
  //
  const { group_pubkey, sec_shares } = pkg
  // Use a t amount of shares to create nonce commitments.
  const members = sec_shares.slice(0, threshold).map(e => {
    return create_commit_pkg(e)
  })
  // Collect the commitments into an array.
  const sec_nonces  = members.map(mbr => mbr.secnonce)
  const pub_nonces  = members.map(mbr => mbr.pubnonce)
  // Compute some context data for the signing session.
  const context     = get_session_ctx(group_pubkey, pub_nonces, message, tweaks)
  // Create the partial signatures for a given signing context.
  const psigs = context.identifiers.map(i => {
    const idx = Number(i)
    const sec_share = get_record(sec_shares, idx)
    const sec_nonce = get_record(sec_nonces, idx)
    const pub_nonce = get_record(pub_nonces, idx)
    const sig_share = sign_msg(context, sec_share, sec_nonce)
    const share_pk  = get_pubkey(sec_share.seckey)

    if (!verify_partial_sig(context, pub_nonce, share_pk, sig_share.psig)) {
      console.log(`psig ${idx}:, ${sig_share.psig}`)
      throw new Error('sig share failed validation')
    }

    return sig_share
  })

  // Aggregate the partial signatures into a single signature.
  const signature = combine_partial_sigs(context, psigs)
  const is_valid  = verify_final_sig(context, message, signature)

  if (!is_valid) {
    throw new Error('final signature failed validation')
  }

  return signature
}
