/**
 * @fileoverview FROST Signing Operations
 *
 * Implements the signing and verification functions for FROST threshold
 * signatures. These functions handle Round 2 (partial signature creation),
 * signature aggregation, and verification.
 *
 * @see https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html
 */

import { Buff, Bytes }     from '@vbyte/buff'
import { schnorr }         from '@noble/curves/secp256k1.js'
import { G }               from '@/ecc/index.js'
import { lift_x, mod_n }   from '@/ecc/util.js'
import { _0n, _1n, _N } from '@/const.js'
import { get_pubkey }      from './helpers.js'
import { interpolate_x }   from './poly.js'

import {
  get_group_binders,
  get_group_prefix,
  get_group_pubnonce,
  get_bind_factor
} from './commit.js'

import {
  hasEvenY,
  type GroupKeyContext,
  type GroupSigningCtx,
  type SecretShare,
  type SecretNonce,
  type ShareSignature,
  type PublicNonce
} from '@/types/index.js'

/**
 * Creates a partial signature for a FROST signing session.
 *
 * This is the Round 2 operation where each participant uses their secret
 * share and secret nonce to produce a partial signature. The partial
 * signatures are later combined to form a valid Schnorr signature.
 *
 * @security CRITICAL: Each secret nonce MUST be used exactly once. Nonce
 *           reuse across different messages allows extraction of the
 *           participant's secret share. The function validates that the
 *           nonce index matches the share index.
 *
 * @param ctx - The group signing context containing challenge, binding factors, etc.
 * @param share - The participant's secret share
 * @param snonce - The participant's secret nonce (must match share index)
 * @returns A partial signature containing the participant's contribution
 * @throws Error if the nonce index does not match the share index
 */
export function sign_msg (
  ctx    : GroupSigningCtx,
  share  : SecretShare,
  snonce : SecretNonce
) : ShareSignature {
  // Unpack the signing context.
  const { bind_factors, challenge, indexes, group_pt } = ctx
  // Get the binding factor for the share.
  const bind_factor = get_bind_factor(bind_factors, share.idx)
  // Get the lagrange coefficient for the share.
  const coefficient = interpolate_x(indexes, BigInt(share.idx))
  // Check that both secrets are for the same share index.
  if (snonce.idx !== share.idx) {
    throw new Error(`commit index does not match share index: ${snonce.idx} !== ${share.idx}`)
  }
  // Convert the secrets to bigints.
  let hidden_nonce = Buff.bytes(snonce.hidden_sn).big,
      binder_nonce = Buff.bytes(snonce.binder_sn).big,
      seckey       = Buff.bytes(share.seckey).big
  // Convert the group pubnonce to a point on the curve.
  const R_elem = lift_x(ctx.group_pn)
  // If the point is odd, negate the nonce values.
  if (!hasEvenY(R_elem)) {
    hidden_nonce = _N - hidden_nonce
    binder_nonce = _N - binder_nonce
  }
  // Initialize the secret key with the proper parity.
  const adjusted_secret = mod_n(group_pt.parity * group_pt.state * seckey)
  // Combine the secret nonces with the binding factor.
  const combined_nonce = mod_n(hidden_nonce + (binder_nonce * bind_factor))
  // Compute the partial signature.
  const partial_sig = mod_n((challenge * coefficient * adjusted_secret) + combined_nonce)
  // Return the partial signature.
  return {
    idx    : share.idx,
    psig   : Buff.big(partial_sig, 32).hex,
    pubkey : get_pubkey(share.seckey)
  }
}

/**
 * Combines partial signatures into a final Schnorr signature.
 *
 * Aggregates all partial signatures from the signing session participants
 * and applies any key tweaks to produce a valid BIP340 Schnorr signature.
 *
 * The final signature is in standard Schnorr format: (R || s) where R is
 * the 32-byte x-coordinate of the group nonce and s is the 32-byte
 * aggregated signature scalar.
 *
 * @param context - The group signing context from the session
 * @param psigs - Array of partial signatures from threshold participants
 * @returns A 64-byte hex-encoded Schnorr signature
 */
export function combine_partial_sigs (
  context : GroupSigningCtx,
  psigs   : ShareSignature[]
) {
  // Unpack the signing context.
  const { challenge, pnonces, group_pt, group_pk, message } = context
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
  const twk = mod_n(challenge * group_pt.parity * group_pt.tweak)
  // Add the tweak to the partial signature.
  const s = mod_n(ps + twk)
  // Return the aggregated signature.
  return Buff.join([ group_pnonce.slice(2), Buff.big(s, 32) ]).hex
}

/**
 * Verifies that a partial signature is valid for the signing session.
 *
 * Checks that a participant's partial signature is correctly formed using
 * their public nonce commitment and share public key. This allows detection
 * of malicious or faulty participants before signature aggregation.
 *
 * The verification equation is: s_i * G = R_i + c * lambda_i * state * P_i
 *
 * @param ctx - The group signing context
 * @param pnonce - The participant's public nonce commitment
 * @param share_pk - The participant's share public key (33-byte compressed)
 * @param share_psig - The participant's partial signature (32-byte hex)
 * @returns True if the partial signature is valid, false otherwise
 */
export function verify_partial_sig (
  ctx        : GroupSigningCtx,
  pnonce     : PublicNonce,
  share_pk   : string,
  share_psig : string,
) {
  // Unpack the signing context.
  const { bind_factors, challenge, indexes, group_pn, group_pt } = ctx
  // Get the binding factor for the share.
  const binder = get_bind_factor(bind_factors, pnonce.idx)
  // Lift the public key elements to points on the curve.
  let hidden_elem = lift_x(pnonce.hidden_pn),
      binder_elem = lift_x(pnonce.binder_pn),
      public_elem = lift_x(share_pk)
  // Lift the group pubnonce to a point on the curve.
  const R_elem = lift_x(group_pn)
  // If the point is odd, negate the nonce values.
  if (!hasEvenY(R_elem)) {
    hidden_elem = G.ScalarMulti(hidden_elem, _N - _1n)
    binder_elem = G.ScalarMulti(binder_elem, _N - _1n)
  }
  // Apply the binding factor to the binder nonce.
  const commit_elem = G.ScalarMulti(binder_elem, binder)
  // Add the hidden and binding nonces.
  const nonce_elem  = G.ElementAdd(hidden_elem, commit_elem)
  // Compute the lagrange coefficient for the share.
  const lambda_i    = interpolate_x(indexes, BigInt(pnonce.idx))
  // Compute the state value.
  const state = mod_n(group_pt.parity * group_pt.state)
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
 * Verifies that a final aggregated signature is valid.
 *
 * Uses standard BIP340 Schnorr signature verification to check the
 * aggregated signature against the group public key and message.
 *
 * @param context - The group key context containing the group public key
 * @param message - The original message that was signed
 * @param signature - The 64-byte aggregated signature to verify
 * @returns True if the signature is valid, false otherwise
 */
export function verify_final_sig (
  context   : GroupKeyContext,
  message   : Bytes,
  signature : Bytes
) {
  const sig = Buff.bytes(signature)
  const msg = Buff.bytes(message)
  const pk  = Buff.hex(context.group_pk.slice(2))
  return schnorr.verify(sig, msg, pk)
}
