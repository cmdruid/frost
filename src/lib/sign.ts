import { Buff, Bytes }     from '@cmdcode/buff'
import { schnorr }         from '@noble/curves/secp256k1'
import { G }               from '@/ecc/index.js'
import { lift_x, mod_n }   from '@/ecc/util.js'
import { _0n, _1n, curve } from '@/const.js'
import { interpolate_x }   from './poly.js'

import { get_bind_factor, get_pubkey } from './util.js'

import {
  get_commit_binders,
  get_commit_prefix,
  get_group_nonce
} from './commit.js'

import type {
  GroupKeyContext,
  GroupSessionCtx,
  SharePackage,
  SecretNoncePackage,
  SignaturePackage,
  PublicNoncePackage
} from '@/types/index.js'

/**
 * Sign a message using a secret share and secret nonce value.
 */
export function sign_msg (
  ctx    : GroupSessionCtx,
  share  : SharePackage,
  snonce : SecretNoncePackage
) : SignaturePackage {
  const { bind_factors, challenge, indexes, group_pt : Q } = ctx
  
  const bind_factor = get_bind_factor(bind_factors, share.idx)
  const coefficient = interpolate_x(indexes, BigInt(share.idx))

  if (snonce.idx !== share.idx) {
    throw new Error(`commit index does not match share index: ${snonce.idx} !== ${share.idx}`)
  }

  // Compute the signature share
  let snonce_h  = Buff.bytes(snonce.hidden_sn).big
  let snonce_b  = Buff.bytes(snonce.binder_sn).big
  let seckey    = Buff.bytes(share.seckey).big

  const GR_elem = lift_x(ctx.group_pn)

  if (!GR_elem.hasEvenY()) {
    snonce_h = curve.n - snonce_h
    snonce_b = curve.n - snonce_b
  }

  let snonce_hbf = mod_n(snonce_h + (snonce_b * bind_factor))

  const sk  = mod_n(Q.parity * Q.state * seckey)
  const sig = mod_n(snonce_hbf + coefficient * sk * challenge)

  return {
    idx    : share.idx,
    psig   : Buff.big(sig, 32).hex,
    pubkey : get_pubkey(share.seckey)
  }
}

/**
 * Combine the signature shares from a FROST signing session.
 */
export function combine_partial_sigs (
  context : GroupSessionCtx,
  psigs   : SignaturePackage[]
) {
  //
  const { challenge, pnonces, group_pt, group_pk, message } = context
  //
  const { parity, tweak } = group_pt
  //
  const commit_prefix = get_commit_prefix(pnonces, group_pk, message)
  // Compute the binding factors
  const group_binders = get_commit_binders(pnonces, commit_prefix)
  // Compute the group commitment
  const group_pnonce  = get_group_nonce(pnonces, group_binders)
  // Compute aggregated signature
  const s = psigs
    .map(e => Buff.hex(e.psig).big)
    .reduce((acc, nxt) => mod_n(acc + nxt), _0n)
  //
  const a = challenge * parity * tweak
  //
  return Buff.join([ group_pnonce.slice(2), Buff.big(mod_n(s + a), 32) ]).hex
}


/**
 * Verify a signature share is valid.
 */
export function verify_partial_sig (
  ctx        : GroupSessionCtx,
  pnonce     : PublicNoncePackage,
  share_pk   : string,
  share_psig : string,
) {
  //
  const { bind_factors, challenge, indexes, group_pk, group_pn } = ctx
  //
  const P_elem = lift_x(group_pk)
  const R_elem = lift_x(group_pn)
  const binder = get_bind_factor(bind_factors, pnonce.idx)

  let hidden_elem = lift_x(pnonce.hidden_pn)
  let binder_elem = lift_x(pnonce.binder_pn)
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
  const lambda_i    = interpolate_x(indexes, BigInt(pnonce.idx))

  const chal = mod_n(challenge * lambda_i)
  const sig  = Buff.hex(share_psig).big
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
  return schnorr.verify(sig, msg, context.group_pk.slice(2))
}
