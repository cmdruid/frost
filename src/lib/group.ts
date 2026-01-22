/**
 * @fileoverview FROST Key Group Generation
 *
 * Provides high-level functions for creating threshold key groups
 * using either a trusted dealer model or for use in DKG protocols.
 */

import { Bytes }    from '@vbyte/buff'
import { _0n, _1n } from '@/const.js'

import {
  create_shares
} from './shares.js'

import {
  create_share_coeffs,
  get_share_commits
} from './vss.js'

import type { SecretShareSet, DealerShareSet } from '@/types/index.js'

/**
 * Creates a secret share set for threshold signing.
 *
 * Generates a polynomial of degree (threshold-1) and evaluates it at
 * indices 1 through share_max to create secret shares. Also generates
 * VSS commitments for share verification.
 *
 * Use this function when implementing DKG, where each participant
 * generates their own share set.
 *
 * @param threshold - Minimum shares required for signing (t in t-of-n)
 * @param share_max - Total number of shares to create (n in t-of-n)
 * @param secrets - Optional pre-determined polynomial coefficients (for determinism)
 * @returns Object containing shares and VSS commitments
 */
export function create_share_set (
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : SecretShareSet {
  if (threshold < 1) {
    throw new Error('threshold must be at least 1')
  }
  if (share_max < 1) {
    throw new Error('share_max must be at least 1')
  }
  if (threshold > share_max) {
    throw new Error('threshold cannot exceed share_max')
  }
  const coeffs      = create_share_coeffs(secrets, threshold)
  const shares      = create_shares(coeffs, share_max)
  const vss_commits = get_share_commits(coeffs)
  return { shares, vss_commits }
}

/**
 * Creates a complete dealer share set including the group public key.
 *
 * This is the high-level function for trusted dealer key generation.
 * The dealer creates all shares and distributes them to participants.
 * The group public key is derived from the first VSS commitment.
 *
 * @security In the trusted dealer model, the dealer knows the full
 *           secret. Use DKG for scenarios requiring no trusted party.
 *
 * @param threshold - Minimum shares required for signing (t in t-of-n)
 * @param share_max - Total number of shares to create (n in t-of-n)
 * @param secrets - Optional pre-determined polynomial coefficients
 * @returns Object containing shares, VSS commitments, and group public key
 */
export function create_dealer_set (
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : DealerShareSet {
  const share_set = create_share_set(threshold, share_max, secrets)
  const group_pk  = share_set.vss_commits[0]
  return { ...share_set, group_pk }
}
