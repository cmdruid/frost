import { Buff, Bytes }     from '@cmdcode/buff'
import { schnorr }         from '@noble/curves/secp256k1'
import { G }               from '@/ecc/index.js'
import { lift_x, mod_n }   from '@/ecc/util.js'
import { _1n, curve }      from '@/ecc/const.js'
import { interpolate_x }   from './poly.js'

import { get_bind_factor, get_pubkey } from './util.js' 

import type {
  PublicNonce,
  SecretNonce,
  SecretShare,
  PartialSignature,
  GroupKeyContext,
  GroupSessionCtx
} from '@/types/index.js'

/**
 * Sign a message using a secret share and secret nonce value.
 */
export function sign_msg (
  context  : GroupSessionCtx,
  secshare : SecretShare,
  secnonce : SecretNonce
) : PartialSignature {
  const { bind_factors, challenge, identifiers, group_state : Q } = context
  
  const bind_factor = get_bind_factor(bind_factors, secshare.idx)
  const coefficient = interpolate_x(identifiers, BigInt(secshare.idx))

  if (secnonce.idx !== secshare.idx) {
    throw new Error('secshare index does not match nonce index')
  }

  // Compute the signature share
  let snonce_h  = Buff.bytes(secnonce.hidden_sn).big
  let snonce_b  = Buff.bytes(secnonce.binder_sn).big
  let seckey    = Buff.bytes(secshare.seckey).big

  const GR_elem = lift_x(context.group_pnonce)

  if (!GR_elem.hasEvenY()) {
    snonce_h = curve.n - snonce_h
    snonce_b = curve.n - snonce_b
  }

  let cnonce = mod_n(snonce_h + (snonce_b * bind_factor))

  const sk  = mod_n(Q.parity * Q.state * seckey)
  const sig = mod_n(cnonce + coefficient * sk * challenge)

  return {
    idx    : secshare.idx,
    pubkey : get_pubkey(secshare.seckey),
    psig   : Buff.big(sig, 32).hex
  }
}

/**
 * Verify a signature share is valid.
 */
export function verify_partial_sig (
  context   : GroupSessionCtx,
  pub_nonce : PublicNonce,
  share_pk  : Bytes,
  share_sig : Bytes,
) {
  //
  const { bind_factors, challenge, identifiers, group_pubkey, group_pnonce } = context
  //
  const P_elem = lift_x(group_pubkey)
  const R_elem = lift_x(group_pnonce)
  const binder = get_bind_factor(bind_factors, pub_nonce.idx)

  let hidden_elem = lift_x(pub_nonce.hidden_pn)
  let binder_elem = lift_x(pub_nonce.binder_pn)
  let public_elem = lift_x(share_pk)

  if (!P_elem.hasEvenY()) {
    public_elem = G.ScalarMulti(public_elem, curve.n - _1n)
  }

  if (!R_elem.hasEvenY()) {
    hidden_elem = G.ScalarMulti(hidden_elem, curve.n - _1n)
    binder_elem = G.ScalarMulti(binder_elem, curve.n - _1n)
  }

  const commit_elem = G.ScalarMulti(binder_elem, binder)
  const nonce_elem  = G.ElementAdd(hidden_elem, commit_elem)
  const lambda_i    = interpolate_x(identifiers, BigInt(pub_nonce.idx))

  const chal = mod_n(challenge * lambda_i)
  const sig  = Buff.bytes(share_sig).big
  const sG   = G.ScalarBaseMulti(sig)
  const pki  = G.ScalarMulti(public_elem, chal)
  const R    = G.ElementAdd(nonce_elem, pki)
  return sG.x === R.x
}

/**
 * Verify that a completed signature is valid.
 */
export function verify_final_sig (
  context   : GroupKeyContext,
  message   : Bytes,
  signature : Bytes
) {
  const sig = Buff.bytes(signature)
  const msg = Buff.bytes(message)
  return schnorr.verify(sig, msg, context.group_pubkey.slice(2))
}
