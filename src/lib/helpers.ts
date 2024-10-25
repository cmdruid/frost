import { Buff, Bytes } from '@cmdcode/buff'
import { hash340 }     from '@cmdcode/crypto-tools/hash'
import { H, G }        from '@/ecc/index.js'
import { _0n, _1n }    from '@/ecc/const.js'
import { assert }      from '@/util/index.js'

import {
  get_group_commit,
  get_bind_factor
} from './util.js'

import type {
  BindFactor,
  CurveElement,
  PublicNonce
} from '@/types/index.js'

/**
 * Generates a secret key.
 */
export function generate_seckey (
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
export function generate_nonce (
  secret    : Bytes,
  aux_seed ?: Bytes
) : Buff {
  const aux = (aux_seed !== undefined)
    ? Buff.bytes(aux_seed, 32)
    : Buff.random(32)
  const secret_seed  = Buff.join([ aux, secret ])
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
  const commit_list = get_group_commit(nonces)
  const commit_hash = H.H5(commit_list)
  return Buff.join([ group_pk, msg_hash, commit_hash ])
}

/**
 * Computes the binding values for each public nonce.
 */
export function compute_nonce_binders (
  nonces : PublicNonce[],
  prefix : Bytes
) : BindFactor[] {
  return nonces.map(({ idx }) => {
    const scalar    = G.SerializeScalar(idx)
    const rho_input = Buff.join([ prefix, scalar ])
    return { idx, key: H.H1(rho_input).hex }
  })
}

/**
 * Computes the group public nonce for the signing session.
 */
export function compute_group_nonce (
  nonces  : PublicNonce[],
  binders : BindFactor[]
) : string {
  let group_commit : CurveElement | null = null

  for (const { idx, binder_pn, hidden_pn } of nonces) {
    const hidden_elem   = G.DeserializeElement(hidden_pn)
    const binding_elem  = G.DeserializeElement(binder_pn)
    const bind_factor   = get_bind_factor(binders, idx)
    const factored_elem = G.ScalarMulti(binding_elem, bind_factor)
    group_commit = G.ElementAdd(group_commit, hidden_elem)
    group_commit = G.ElementAdd(group_commit, factored_elem)
  }
  assert.exists(group_commit)
  return G.SerializeElement(group_commit).hex
}

/**
 * Computes a BIP340 compatible challenge message.
 */
export function get_bip340_challenge (
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
