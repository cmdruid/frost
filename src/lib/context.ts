/**
 * @fileoverview FROST Signing Context Management
 *
 * Provides functions to construct the signing context needed for FROST
 * operations. The context encapsulates key state, commitment data, and
 * challenge computation.
 */

import { Buff, Bytes }     from '@vbyte/buff'
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
 * Computes the group key context with optional Taproot-style tweaks.
 *
 * Creates the key context needed for signing, including the internal
 * public key, tweaked group public key, and parity state for BIP340
 * compatibility.
 *
 * @param pubkey - The internal group public key (pre-tweak)
 * @param tweaks - Optional array of tweaks to apply (e.g., Taproot tweak)
 * @returns The group key context with parity state
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
 * Computes the commitment context for a signing session.
 *
 * Given the key context and participant commitments, computes all
 * session-specific values: binding factors, group nonce, challenge, etc.
 *
 * @param key_ctx - The group key context
 * @param pnonces - Array of public nonce commitments from participants
 * @param message - The message to be signed (hex-encoded)
 * @returns The commitment context containing all session binding data
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
 * Computes the complete signing context for a FROST session.
 *
 * This is the main entry point for context creation. It combines the
 * key context and commitment context into a single object that contains
 * all information needed for signing operations.
 *
 * @param group_pk - The group public key (internal, pre-tweak)
 * @param pnonces - Array of public nonce commitments from threshold participants
 * @param message - The message to be signed (hex-encoded)
 * @param tweaks - Optional array of key tweaks (e.g., for Taproot)
 * @returns The complete signing context for use in sign_msg()
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
