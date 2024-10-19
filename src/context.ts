import { Buff, Bytes } from '@cmdcode/buff'
import { lift_x }      from './util.js'
import { _1n }         from './ecc/const.js'

import { get_nonce_identifiers } from './util.js' 

import {
  CommitContext,
  KeyContext,
  PublicNonce
} from './types.js'

import {
  compute_nonce_binders,
  compute_bip340_challenge,
  get_commit_prefix,
  compute_group_nonce,
  get_point_state,
} from './helpers.js'

/**
 * Get the initial context of the group key, plus any tweaks.
 */
export function get_key_context (
  group_pk : Bytes,
  tweaks  ?: Bytes[]
) : KeyContext {
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
  context    : KeyContext,
  pub_nonces : PublicNonce[],
  message    : Bytes,
) : CommitContext {
  // Set the group pubkey from the key context.
  const group_pubkey = context.group_pubkey
  // Calculate the prefix for making the binding commitments.
  const bind_prefix  = get_commit_prefix(pub_nonces, group_pubkey, message).hex
  // Compute the binding values for each nonce.
  const bind_factors = compute_nonce_binders(pub_nonces, bind_prefix)
  // Compute the group nonce value.
  const group_pnonce = compute_group_nonce(pub_nonces, bind_factors)
  // Compile a list of identifiers from the nonces.
  const identifiers  = get_nonce_identifiers(pub_nonces)
  // Compute the challenge hash for the signing session.
  const challenge    = compute_bip340_challenge(group_pnonce, group_pubkey, message)
  // Format the message to be signed as a hex string.
  message = Buff.bytes(message).hex
  // Return the context object.
  return {
    ...context, bind_prefix, bind_factors, challenge,
    pub_nonces, group_pnonce, identifiers, message
  }
}

/**
 * Get the full context of the signing session.
 */
export function get_full_context (
  group_pk   : Bytes,
  pub_nonces : PublicNonce[],
  message    : Bytes,
  tweaks    ?: Bytes[]
) : CommitContext {
  // Get the key context for the session.
  const key_ctx = get_key_context(group_pk, tweaks)
  // Get the remaining context for the session.
  const com_ctx = get_commit_context(key_ctx, pub_nonces, message)
  // Return the full context object.
  return com_ctx
}
