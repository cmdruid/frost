import { Buff, Bytes }     from '@cmdcode/buff'
import { schnorr }         from '@noble/curves/secp256k1'
import { G }               from '@/ecc/index.js'
import { lift_x, mod_n }   from '@/ecc/util.js'
import { _0n, _1n, CURVE } from '@/const.js'
import { get_pubkey }      from './helpers.js'
import { interpolate_x }   from './poly.js'

import {
  get_group_binders,
  get_group_prefix,
  get_group_pubnonce,
  get_bind_factor
} from './commit.js'

import type {
  GroupKeyContext,
  GroupSigningCtx,
  SecretShare,
  SecretNonce,
  ShareSignature,
  PublicNonce
} from '@/types/index.js'

/**
 * Sign a message using a secret share and secret nonce value.
 */
export function sign_msg (
  ctx    : GroupSigningCtx,
  share  : SecretShare,
  snonce : SecretNonce
) : ShareSignature {
  // Unpack the signing context.
  const { bind_factors, challenge, indexes, group_pt : Q } = ctx
  // Get the binding factor for the share.
  const bind_factor = get_bind_factor(bind_factors, share.idx)
  // Get the lagrange coefficient for the share.
  const coefficient = interpolate_x(indexes, BigInt(share.idx))
  // Check that both secrets are for the same share index.
  if (snonce.idx !== share.idx) {
    throw new Error(`commit index does not match share index: ${snonce.idx} !== ${share.idx}`)
  }
  // Convert the secrets to bigints.
  let snonce_h  = Buff.bytes(snonce.hidden_sn).big,
      snonce_b  = Buff.bytes(snonce.binder_sn).big,
      seckey    = Buff.bytes(share.seckey).big
  // Convert the group pubnonce to a point on the curve.
  const R_elem = lift_x(ctx.group_pn)
  // If the point is odd, negate the nonce values.
  if (!R_elem.hasEvenY()) {
    snonce_h = CURVE.n - snonce_h
    snonce_b = CURVE.n - snonce_b
  }
  // Initialize the secret key with the proper parity.
  const sk = mod_n(Q.parity * Q.state * seckey)
  // Combine the secret nonces with the binding factor.
  const nk = mod_n(snonce_h + (snonce_b * bind_factor))
  // Compute the partial signature.
  const ps = mod_n((challenge * coefficient * sk) + nk)
  // Return the partial signature.
  return {
    idx    : share.idx,
    psig   : Buff.big(ps, 32).hex,
    pubkey : get_pubkey(share.seckey)
  }
}

/**
 * Combine the signature shares from a FROST signing session.
 */
export function combine_partial_sigs (
  context : GroupSigningCtx,
  psigs   : ShareSignature[]
) {
  // Unpack the signing context.
  const { challenge, pnonces, group_pt: Q, group_pk, message } = context
  // Compute the group prefix.
  const commit_prefix = get_group_prefix(pnonces, group_pk, message)
  // Compute the binding factors.
  const group_binders = get_group_binders(pnonces, commit_prefix)
  // Compute the group pubnonce.
  const group_pnonce  = get_group_pubnonce(pnonces, group_binders)
  // Compute the aggregated signature.
  const ps = psigs
    .map(e => Buff.hex(e.psig).big)
    .reduce((acc, nxt) => mod_n(acc + nxt), _0n)
  // Compute the final tweak value.
  const twk = mod_n(challenge * Q.parity * Q.tweak)
  // Add the tweak to the partial signature.
  const s = mod_n(ps + twk)
  // Return the aggregated signature.
  return Buff.join([ group_pnonce.slice(2), Buff.big(s, 32) ]).hex
}

/**
 * Verify a signature share is valid.
 */
export function verify_partial_sig (
  ctx        : GroupSigningCtx,
  pnonce     : PublicNonce,
  share_pk   : string,
  share_psig : string,
) {
  // Unpack the signing context.
  const { bind_factors, challenge, indexes, group_pn, group_pt: Q } = ctx
  // Get the binding factor for the share.
  const binder = get_bind_factor(bind_factors, pnonce.idx)
  // Lift the public key elements to points on the curve.
  let hidden_elem = lift_x(pnonce.hidden_pn),
      binder_elem = lift_x(pnonce.binder_pn),
      public_elem = lift_x(share_pk)
  // Lift the group pubnonce to a point on the curve.
  const R_elem = lift_x(group_pn)
  // If the point is odd, negate the nonce values.
  if (!R_elem.hasEvenY()) {
    hidden_elem = G.ScalarMulti(hidden_elem, CURVE.n - _1n)
    binder_elem = G.ScalarMulti(binder_elem, CURVE.n - _1n)
  }
  // Apply the binding factor to the binder nonce.
  const commit_elem = G.ScalarMulti(binder_elem, binder)
  // Add the hidden and binding nonces.
  const nonce_elem  = G.ElementAdd(hidden_elem, commit_elem)
  // Compute the lagrange coefficient for the share.
  const lambda_i    = interpolate_x(indexes, BigInt(pnonce.idx))
  // Compute the state value.
  const state = mod_n(Q.parity * Q.state)
  // Compute the challenge value.
  const chal  = mod_n(challenge * lambda_i * state)
  // Convert the partial signature to a bigint.
  const sig   = Buff.hex(share_psig).big
  // Lift the partial signature to a point on the curve.
  const sG    = G.ScalarBaseMulti(sig)
  // Compute the public key point.
  const pki   = G.ScalarMulti(public_elem, chal)
  // Add the nonce and public key points.
  const R     = G.ElementAdd(nonce_elem, pki)
  // Return true if the points are equal.
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
