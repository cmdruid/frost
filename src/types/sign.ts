/**
 * @fileoverview FROST Signing Type Definitions
 *
 * Types for representing participant profiles and partial signatures
 * during FROST signing operations.
 */

import { CommitmentPackage } from './commit.js'
import { SecretShare }   from './share.js'

/**
 * A participant's complete profile for a signing session.
 *
 * Combines the participant's secret share with their commitment
 * for the current signing round.
 *
 * @property idx - The participant's 1-based index
 * @property commit - The commitment package for this signing session
 * @property share - The participant's secret share
 */
export interface ShareProfile {
  /** The participant's 1-based index */
  idx    : number
  /** The commitment package for this signing session */
  commit : CommitmentPackage
  /** The participant's secret share */
  share  : SecretShare
}

/**
 * A participant's partial signature contribution.
 *
 * Created during Round 2 of FROST signing. Partial signatures are
 * aggregated to produce the final Schnorr signature.
 *
 * @property idx - The participant's 1-based index
 * @property pubkey - The participant's share public key (for verification)
 * @property psig - The partial signature as a 32-byte hex string
 */
export interface ShareSignature {
  /** The participant's 1-based index */
  idx    : number
  /** The participant's share public key (33-byte compressed hex) */
  pubkey : string
  /** The partial signature (32-byte hex) */
  psig   : string
}
