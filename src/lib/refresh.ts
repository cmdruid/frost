/**
 * @fileoverview FROST Share Refresh Protocol
 *
 * Implements proactive share refresh, allowing participants to update
 * their shares while maintaining the same group public key and threshold.
 * This protects against gradual share compromise over time.
 */

import { Bytes }    from '@vbyte/buff'
import { _0n, _1n } from '@/const.js'

import {
  combine_set,
  create_shares
} from './shares.js'

import {
  create_share_coeffs,
  get_share_commits
} from './vss.js'

import type { SecretShare, SecretSharePackage } from '@/types/index.js'

/**
 * Generates refresh shares for proactive share update.
 *
 * Creates a polynomial with zero constant term (f(0) = 0) so that when
 * refresh shares are added to existing shares, the secret remains unchanged
 * but all shares get new values.
 *
 * Each participant generates their own refresh shares and distributes them.
 * After all refresh shares are collected and applied, the original shares
 * become invalid.
 *
 * @param index - The index of the participant generating refresh shares
 * @param threshold - The threshold value (t in t-of-n)
 * @param share_max - Total number of shares (n in t-of-n)
 * @param secrets - Optional pre-determined coefficients (for determinism)
 * @returns Package containing refresh shares and VSS commitments
 */
export function gen_refresh_shares (
  index     : number,
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : SecretSharePackage {
  const sub_coeffs = create_share_coeffs(secrets, threshold - 1)
  const coeffs = [ _0n, ...sub_coeffs ]
  const shares = create_shares(coeffs, share_max)
  const vss_commits = get_share_commits(sub_coeffs)
  return { vss_commits, idx: index, shares }
}

/**
 * Applies refresh shares to update a participant's share.
 *
 * Combines the current share with all received refresh shares to produce
 * a new share. The new share corresponds to the same secret but cannot
 * be combined with old shares from other participants.
 *
 * @param refresh_shares - Array of refresh shares from other participants
 * @param current_share - The participant's current secret share
 * @returns The updated secret share
 */
export function refresh_share (
  refresh_shares : SecretShare[],
  current_share  : SecretShare
) : SecretShare {
  const shares = [ current_share, ...refresh_shares ]
  return combine_set(shares)
}
