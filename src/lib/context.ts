import { Buff, Bytes }     from '@cmdcode/buff'
import { _1n, _N }         from '@/const.js'
import { get_point_state } from '@/ecc/state.js'
import { lift_x }          from '@/ecc/util.js'
import { get_challenge }   from '@/lib/helpers.js'

import {
  get_group_binders,
  get_group_prefix,
  get_group_pubnonce,
  get_nonce_ids
} from './commit.js'

import type {
  GroupCommitContext,
  GroupKeyContext,
  GroupSigningCtx,
  PublicNonce
} from '@/types/index.js'

/**
 * Get the initial context of the group key, plus any tweaks.
 */
export function get_group_key_context (
  pubkey  : Bytes,
  tweaks? : Bytes[]
) : GroupKeyContext {
  // Initialize internal pubkey as group pubkey.
  const int_pk   = Buff.bytes(pubkey).hex
  // Get initial state of pubkey as internal state.
  const int_pt   = lift_x(int_pk)
  // Calculate the group state (with any additional tweaks).
  const group_pt = get_point_state(int_pt, tweaks)
  // Set the group pubkey based on the group point (after tweaks).
  const group_pk = group_pt.point.toHex(true)
  // Return both keys and states.
  return { int_pk, int_pt, group_pk, group_pt }
}

/**
 * Get the remaining context of the signing session.
 */
export function get_group_commit_context (
  key_ctx : GroupKeyContext,
  pnonces : PublicNonce[],
  message : string,
) : GroupCommitContext {
  // Set the group pubkey from the key context.
  const group_pubkey = key_ctx.group_pk
  // Calculate the prefix for making the binding commitments.
  const bind_prefix  = get_group_prefix(pnonces, group_pubkey, message).hex
  // Compute the binding values for each nonce.
  const bind_factors = get_group_binders(pnonces, bind_prefix)
  // Compute the group nonce value.
  const group_pn     = get_group_pubnonce(pnonces, bind_factors)
  // Compile a list of identifiers from the nonces.
  const indexes      = get_nonce_ids(pnonces)
  // Compute the challenge hash for the signing session.
  const challenge    = get_challenge(group_pn, group_pubkey, message)
  // Format the message to be signed as a hex string.
  message = Buff.bytes(message).hex
  // Return the context object.
  return { bind_prefix, bind_factors, challenge, pnonces, group_pn, indexes, message }
}

/**
 * Get the full context of the signing session.
 */
export function get_group_signing_ctx (
  group_pk : Bytes,
  pnonces  : PublicNonce[],
  message  : string,
  tweaks?  : string[]
) : GroupSigningCtx {
  // Get the key context for the session.
  const key_ctx = get_group_key_context(group_pk, tweaks)
  // Get the remaining context for the session.
  const com_ctx = get_group_commit_context(key_ctx, pnonces, message)
  // Return the full context object.
  return { ...key_ctx, ...com_ctx }
}
