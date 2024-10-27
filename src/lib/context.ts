import { Buff, Bytes }       from '@cmdcode/buff'
import { _1n }               from '@/ecc/const.js'
import { get_point_state }   from '@/ecc/state.js'
import { lift_x }            from '@/ecc/util.js'
import { create_share_pkg }  from './shares.js'
import { create_commit_pkg } from './proto.js'

import { get_nonce_ids, get_pubkey } from './util.js' 

import {
  compute_nonce_binders,
  get_bip340_challenge,
  get_commit_prefix,
  compute_group_nonce
} from './helpers.js'

import type {
  CommitPackage,
  DealerPackage,
  GroupCommitContext,
  GroupKeyContext,
  GroupSessionCtx,
  PublicNonce,
  SecretPackage
} from '@/types/index.js'

/**
 * Get the initial context of the group key, plus any tweaks.
 */
export function get_key_context (
  group_pk : Bytes,
  tweaks  ?: Bytes[]
) : GroupKeyContext {
  // Initialize internal pubkey as group pubkey.
  const int_pubkey   = Buff.bytes(group_pk).hex
  // Get initial state of pubkey as internal state.
  const int_state    = get_point_state(lift_x(group_pk))
  // Calculate the group state (with any additional tweaks).
  const group_state  = get_point_state(int_state.point, tweaks)
  // Set the group pubkey based on the group point (after tweaks).
  const group_pubkey = group_state.point.toHex(true)
  // Return both keys and states.
  return { int_pubkey, int_state, group_pubkey, group_state }
}

/**
 * Get the remaining context of the signing session.
 */
export function get_commit_context (
  context    : GroupKeyContext,
  pub_nonces : PublicNonce[],
  message    : Bytes,
) : GroupCommitContext {
  // Set the group pubkey from the key context.
  const group_pubkey = context.group_pubkey
  // Calculate the prefix for making the binding commitments.
  const bind_prefix  = get_commit_prefix(pub_nonces, group_pubkey, message).hex
  // Compute the binding values for each nonce.
  const bind_factors = compute_nonce_binders(pub_nonces, bind_prefix)
  // Compute the group nonce value.
  const group_pnonce = compute_group_nonce(pub_nonces, bind_factors)
  // Compile a list of identifiers from the nonces.
  const identifiers  = get_nonce_ids(pub_nonces)
  // Compute the challenge hash for the signing session.
  const challenge    = get_bip340_challenge(group_pnonce, group_pubkey, message)
  // Format the message to be signed as a hex string.
  message = Buff.bytes(message).hex
  // Return the context object.
  return {
    bind_prefix, bind_factors, challenge,
    pub_nonces, group_pnonce, identifiers, message
  }
}

/**
 * Get the full context of the signing session.
 */
export function get_session_ctx (
  group_pk   : Bytes,
  pub_nonces : PublicNonce[],
  message    : Bytes,
  tweaks    ?: Bytes[]
) : GroupSessionCtx {
  // Get the key context for the session.
  const key_ctx = get_key_context(group_pk, tweaks)
  // Get the remaining context for the session.
  const com_ctx = get_commit_context(key_ctx, pub_nonces, message)
  // Return the full context object.
  return { ...key_ctx, ...com_ctx }
}

export function get_dealer_ctx (
  seeds     : string[],
  share_ct  : number,
  threshold : number
) : DealerPackage {
  const share_pkg = create_share_pkg(seeds, threshold, share_ct)
  const group_pk  = share_pkg.group_pubkey
  const commits : CommitPackage[] = []
  const secrets : SecretPackage[] = [] 

  for (const share of share_pkg.sec_shares) {
    const { idx, seckey } = share
    const pubkey    = get_pubkey(seckey)
    const nonce_pkg = create_commit_pkg(share)
    const { binder_sn, hidden_sn } = nonce_pkg.secnonce
    const { binder_pn, hidden_pn } = nonce_pkg.pubnonce
    commits.push({ idx, binder_pn, hidden_pn, share_pk: pubkey })
    secrets.push({ idx, binder_sn, hidden_sn, share_sk: seckey })
  }

  return { commits, group_pk, secrets, threshold }
}
