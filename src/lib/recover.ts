/**
 * @fileoverview FROST Share Recovery Protocol
 *
 * Implements share recovery, allowing a group to reconstruct a lost
 * participant's share using threshold cooperation. This enables key
 * recovery without exposing the group secret.
 */

import { Buff, Bytes } from '@vbyte/buff'
import { mod_n }  from '@/ecc/util.js'
import { assert } from '@/util/index.js'
import { _0n }    from '@/const.js'

import { calc_lagrange_coeff } from './poly.js'

import {
  create_share_coeffs,
  get_share_commits
} from './vss.js'

import type { SecretShare, SecretSharePackage }  from '@/types/index.js'

/**
 * Generates recovery share contributions for reconstructing a lost share.
 *
 * Each participating member creates a recovery share package using their
 * secret share and Lagrange interpolation. The recovery shares are designed
 * so that when combined, they reconstruct the target's original share.
 *
 * The protocol uses verifiable secret sharing to allow verification of
 * each contribution without revealing the final recovered share prematurely.
 *
 * @param members - Array of all participating member indices (must include share.idx)
 * @param share - The participant's secret share
 * @param target - The index of the share being recovered
 * @param threshold - The threshold value (minimum members needed)
 * @param secrets - Optional pre-determined coefficients (for determinism)
 * @returns Package containing recovery shares and VSS commitments
 * @throws Error if not enough members to meet threshold
 */
export function gen_recovery_shares (
  members   : number[],
  share     : SecretShare,
  target    : number,
  threshold : number,
  secrets   : Bytes[] = []
) : SecretSharePackage {
  assert.ok(members.length >= threshold, 'not enough members to meet threshold')
  members = [...members].sort()
  const share_idx  = BigInt(share.idx)
  const target_idx = BigInt(target)
  const mbrs = members
    .filter(idx => idx !== share.idx)
    .map(i => BigInt(i))
  const share_seckey  = Buff.hex(share.seckey).big
  const lgrng_coeff   = calc_lagrange_coeff(mbrs, share_idx, target_idx)
  assert.ok(lgrng_coeff > _0n, 'lagrange coefficient must be greater than zero')
  const rand_coeffs   = create_share_coeffs(secrets, threshold - 1)
  const coeff_sum     = rand_coeffs.reduce((p, n) => mod_n(p + n), _0n)
  const repair_coeff  = mod_n((lgrng_coeff * share_seckey) - coeff_sum)
  const repair_shares = [ ...rand_coeffs, repair_coeff ]
  const vss_commits   = get_share_commits(repair_shares)
  const shares = members.map((idx, i) => {
    return { idx, seckey: Buff.big(repair_shares[i]).hex }
  })
  return { idx: share.idx, vss_commits, shares }
}

/**
 * Recovers a member's share from aggregated recovery contributions.
 *
 * After collecting recovery share contributions from threshold participants,
 * this function combines them to reconstruct the original share.
 *
 * @param shares - Array of aggregated recovery shares from participants
 * @param idx - The index of the share being recovered
 * @returns The recovered secret share
 */
export function recover_share (
  shares : SecretShare[],
  idx    : number
) : SecretShare {
  const coeffs = shares.map(e => Buff.hex(e.seckey).big)
  const summed = coeffs.reduce((p, n) => mod_n(p + n), _0n)
  return { idx, seckey: Buff.big(summed).hex }
}
