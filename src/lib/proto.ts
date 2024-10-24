import { Buff, Bytes } from '@cmdcode/buff'
import { _0n }         from '@/ecc/const.js'
import { mod_n }       from '@/ecc/util.js'
import { get_pubkey }  from './util.js'

import {
  compute_group_nonce,
  compute_nonce_binders,
  get_commit_prefix,
  generate_nonce
} from './helpers.js'

import type {
  GroupSessionCtx,
  NoncePackage,
  PartialSignature,
  SecretShare,
} from '@/types/index.js'

/**
 * Creates a commitment package for a FROST signing session.
 */
export function create_nonce_pkg (
  secret_share : SecretShare,
  hidden_seed ?: Bytes,
  binder_seed ?: Bytes
) : NoncePackage {
  const { idx, seckey } = secret_share
  const binder_sn = generate_nonce(seckey, binder_seed).hex
  const hidden_sn = generate_nonce(seckey, hidden_seed).hex
  const binder_pn = get_pubkey(binder_sn)
  const hidden_pn = get_pubkey(hidden_sn)
  const secnonce  = { idx, binder_sn, hidden_sn }
  const pubnonce  = { idx, binder_pn, hidden_pn }
  return { idx, pubnonce, secnonce }
}

/**
 * Combine the signature shares from a FROST signing session.
 */
export function combine_partial_sigs (
  context : GroupSessionCtx,
  psigs   : PartialSignature[]
) {
  //
  const { challenge, pub_nonces, group_state, group_pubkey, message } = context
  //
  const { parity, tweak } = group_state
  //
  const commit_prefix = get_commit_prefix(pub_nonces, group_pubkey, message)
  // Compute the binding factors
  const group_binders = compute_nonce_binders(pub_nonces, commit_prefix)
  // Compute the group commitment
  const group_pnonce  = compute_group_nonce(pub_nonces, group_binders)
  // Compute aggregated signature
  const s = psigs
    .map(e => Buff.hex(e.psig).big)
    .reduce((acc, nxt) => mod_n(acc + nxt), _0n)
  //
  const a = challenge * parity * tweak
  //
  return Buff.join([ group_pnonce.slice(2), Buff.big(mod_n(s + a), 32) ]).hex
}
