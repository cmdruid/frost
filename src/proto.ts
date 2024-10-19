import { Buff, Bytes }    from '@cmdcode/buff'
import { get_pubkey }     from './util.js'
import { _0n }            from './ecc/const.js'
import { mod_n }          from './ecc/util.js'

import { CommitContext, NonceData, SecretShare, SignatureShare } from './types.js'

import {
  compute_group_nonce,
  compute_nonce_binders,
  get_commit_prefix,
  nonce_generate
} from './helpers.js'

/**
 * Creates a commitment package for a FROST signing session.
 */
export function create_commitment (
  secshare     : SecretShare,
  hidden_seed ?: Bytes,
  binder_seed ?: Bytes
) : NonceData {
  const { idx, seckey } = secshare
  const snonce_h = nonce_generate(seckey, hidden_seed).hex
  const snonce_b = nonce_generate(seckey, binder_seed).hex
  const pnonce_h = get_pubkey(snonce_h)
  const pnonce_b = get_pubkey(snonce_b)
  const sec_nonces = { idx, snonce_h, snonce_b }
  const pub_nonces = { idx, pnonce_h, pnonce_b }
  return { sec_nonces, pub_nonces }
}

/**
 * Combine the signature shares from a FROST signing session.
 */
export function combine_sig_shares (
  context    : CommitContext,
  sig_shares : SignatureShare[]
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
  const s = sig_shares
    .map(e => Buff.hex(e.sig).big)
    .reduce((acc, nxt) => mod_n(acc + nxt), _0n)
  //
  const a = challenge * parity * tweak
  //
  return Buff.join([ group_pnonce.slice(2), Buff.big(mod_n(s + a), 32) ]).hex
}
