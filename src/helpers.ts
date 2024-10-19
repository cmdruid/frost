import { Buff, Bytes }  from '@cmdcode/buff'
import { hash340 }      from '@cmdcode/crypto-tools/hash'
import { H, G }         from './ecc/index.js'
import { CurveElement } from './ecc/types.js'
import { mod_n }        from './ecc/util.js'
import * as assert      from './assert.js'

import { _0n, _1n, curve } from './ecc/const.js'

import { NonceBinder, PointState, PublicNonce }      from './types.js'
import { encode_group_commit_list, get_bind_factor } from './util.js'

/**
 * Generates a secret key.
 */
export function seckey_generate (
  aux ?: Bytes
) : Buff {
  const aux_bytes = (aux !== undefined)
    ? Buff.bytes(aux, 32)
    : Buff.random(32)
  return H.H3(aux_bytes)
}

/**
 * Generates a secret nonce using a secret key, and optional auxiliary value.
 */
export function nonce_generate (
  secret : Bytes,
  aux   ?: Bytes
) : Buff {
  const aux_bytes = (aux !== undefined)
    ? Buff.bytes(aux, 32)
    : Buff.random(32)
  const secret_seed  = Buff.join([ aux_bytes, secret ])
  return H.H3(secret_seed)
}

/**
 * Constructs a byte-prefix for the signing session.
 */
export function get_commit_prefix (
  nonces   : PublicNonce[],
  group_pk : Bytes,
  message  : Bytes
) : Buff {
  const msg_bytes   = Buff.bytes(message)
  const msg_hash    = H.H4(msg_bytes)
  const commit_list = encode_group_commit_list(nonces)
  const commit_hash = H.H5(commit_list)
  return Buff.join([ group_pk, msg_hash, commit_hash ])
}

/**
 * Computes the binding values for each public nonce.
 */
export function compute_nonce_binders (
  nonces : PublicNonce[],
  prefix : Bytes
) : NonceBinder[] {
  return nonces.map(({ idx }) => {
    const scalar    = G.SerializeScalar(idx)
    const rho_input = Buff.join([ prefix, scalar ])
    return { idx, key : H.H1(rho_input).hex }
  })
}

/**
 * Computes the group public nonce for the signing session.
 */
export function compute_group_nonce (
  nonces  : PublicNonce[],
  binders : NonceBinder[]
) : string {
  let group_commit : CurveElement | null = null

  for (const { idx, pnonce_h, pnonce_b } of nonces) {
    const hidden_elem   = G.DeserializeElement(pnonce_h)
    const binding_elem  = G.DeserializeElement(pnonce_b)
    const bind_factor   = get_bind_factor(binders, idx)
    const factored_elem = G.ScalarMulti(binding_elem, bind_factor)
    // We need to add these elements.
    // G.ElementAdd(group_commit, hidden_nonce_commit)
    group_commit = G.ElementAdd(group_commit, hidden_elem)
    group_commit = G.ElementAdd(group_commit, factored_elem)
  }
  assert.exists(group_commit)
  return G.SerializeElement(group_commit).hex
}

/**
 * Computes a BIP340 compatible challenge message.
 */
export function compute_bip340_challenge (
  group_pnonce : Bytes,
  group_pubkey : Bytes,
  message      : Bytes
) {
  const grp_pk = Buff.bytes(group_pubkey).slice(1)
  const grp_pn = Buff.bytes(group_pnonce).slice(1)
  assert.size(grp_pk, 32)
  assert.size(grp_pn, 32)
  return hash340('BIP0340/challenge', grp_pn, grp_pk, message).big
}

/**
 * Computes the accumulative parity state for a given point,
 * with optional key tweaks provided.
 */
export function get_point_state (
  element : CurveElement,
  tweaks  : Bytes[] = []
) : PointState {
  // Convert our tweaks to bigints.
  const ints = tweaks.map(e => mod_n(Buff.bytes(e).big))
  // Define the positive scalar.
  const pos  = BigInt(1)
  // Define the negative (inverse) scalar.
  const neg  = curve.n - pos

  let point : CurveElement = element,
      parity = pos, // Handles negation for current round.
      state  = pos, // Tracks negation state across rounds.
      tweak  = 0n   // Stores the accumulated (negated) tweak.

  for (const t of ints) {
    // If point is odd, g should be negative.
    parity = (!point.hasEvenY()) ? neg : pos
    // Invert point based on g, then add tweak.
    point  = G.ElementAdd(G.ScalarMulti(point, parity), G.ScalarBaseMulti(t))
    // Assert that point is not null.
    point.assertValidity()
    // Store our progress for the next round.
    state = mod_n(parity * state)
    tweak = mod_n(t + parity * tweak)
  }
  
  // Set parity to the current point state.
  parity = (!point.hasEvenY()) ? neg : pos

  return { point, parity, state, tweak }
}
