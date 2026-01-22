/**
 * @fileoverview FROST Signing Context Type Definitions
 *
 * Types for the signing context objects that encapsulate all state
 * needed for FROST signing operations.
 */

import { CurveElement, PointState } from './ecc.js'

import { BindFactor, PublicNonce } from './commit.js'

/**
 * The complete signing context combining key and commitment contexts.
 *
 * Contains all information needed to perform signing operations:
 * key state, commitment data, binding factors, and challenge.
 */
export type GroupSigningCtx = GroupKeyContext & GroupCommitContext

/**
 * Context for the group key with optional Taproot-style tweaks.
 *
 * Encapsulates the key state including parity tracking for BIP340
 * compatibility. When tweaks are applied (e.g., Taproot), the internal
 * and group keys may differ.
 *
 * @property group_pt - The point state with parity tracking for the group key
 * @property group_pk - The group public key (possibly tweaked, 33-byte hex)
 * @property int_pt - The internal (pre-tweak) point (optional)
 * @property int_pk - The internal (pre-tweak) public key (optional, 33-byte hex)
 * @property tweak - The applied tweak value (optional, 32-byte hex)
 */
export interface GroupKeyContext {
  /** The point state with parity tracking for the group key */
  group_pt : PointState
  /** The group public key (possibly tweaked, 33-byte compressed hex) */
  group_pk : string
  /** The internal (pre-tweak) curve element (optional) */
  int_pt  ?: CurveElement
  /** The internal (pre-tweak) public key (optional, 33-byte hex) */
  int_pk  ?: string
  /** The applied tweak value (optional, 32-byte hex) */
  tweak   ?: string
}

/**
 * Context for a signing session's commitment phase.
 *
 * Contains all session-specific data computed from the commitments
 * and message: binding factors, group nonce, challenge, etc.
 *
 * @property bind_factors - Array of binding factors for each participant
 * @property bind_prefix - The encoded prefix for binding factor computation
 * @property challenge - The Schnorr challenge value (e = H(R || P || m))
 * @property group_pn - The aggregated group public nonce (R)
 * @property indexes - Array of participating member indices as bigints
 * @property message - The message being signed (hex-encoded)
 * @property pnonces - Array of public nonces from all participants
 */
export interface GroupCommitContext {
  /** Array of binding factors for each participant */
  bind_factors : BindFactor[],
  /** The encoded prefix for binding factor computation */
  bind_prefix  : string,
  /** The Schnorr challenge value (e = H(R || P || m)) */
  challenge    : bigint,
  /** The aggregated group public nonce (33-byte compressed hex) */
  group_pn     : string,
  /** Array of participating member indices as bigints */
  indexes      : bigint[],
  /** The message being signed (hex-encoded) */
  message      : string,
  /** Array of public nonces from all participants */
  pnonces      : PublicNonce[]
}
