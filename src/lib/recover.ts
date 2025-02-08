import { Buff }   from '@cmdcode/buff'
import { mod_n }  from '@/ecc/util.js'
import { assert } from '@/util/index.js'
import { _0n }    from '@/const.js'

import { calc_lagrange_coeff } from './poly.js'

import {
  create_share_coeffs,
  get_share_commits
} from './vss.js'

import type { SecretShare, SecretSharePackage }  from '@/types/index.js'

export function gen_recovery_shares (
  members   : number[],
  share     : SecretShare,
  target    : number,
  threshold : number,
  secrets   : string[] = []
) : SecretSharePackage {
  assert.ok(members.length >= threshold, 'not enough members to meet threshold')
  // 
  members = members.sort()
  // Convert share index to bigint.
  const share_idx  = BigInt(share.idx)
  // Convert target index to bigint.
  const target_idx = BigInt(target)
  // Remove provided share from members list.
  const mbrs = members
    .filter(idx => idx !== share.idx)
    .map(i => BigInt(i))
  // Convert participant share to bigint.
  const share_seckey  = Buff.hex(share.seckey).big
  // Generate largrange coefficient for the missing share.
  const lgrng_coeff   = calc_lagrange_coeff(mbrs, share_idx, target_idx)
  // Assert the lagrange coefficient is greater than zero.
  assert.ok(lgrng_coeff > _0n, 'lagrange coefficient must be greater than zero')
  // Generate a new set of random coefficients.
  const rand_coeffs   = create_share_coeffs(secrets, threshold - 1)
  // Sum the coefficients 
  const coeff_sum     = rand_coeffs.reduce((p, n) => mod_n(p + n), _0n)
  // Compute the final repair coefficient.
  const repair_coeff  = mod_n((lgrng_coeff * share_seckey) - coeff_sum)
  // Collect the coeffs together as repair shares.
  const repair_shares = [ ...rand_coeffs, repair_coeff ]
  // Get commitments for all repair shares.
  const vss_commits   = get_share_commits(repair_shares)
  //
  const shares = members.map((idx, i) => {
    return { idx, seckey: Buff.big(repair_shares[i]).hex }
  })
  // Return repair package.
  return { idx: share.idx, vss_commits, shares }
}

/**
 * Recover a member's share using a set of aggregated
 * recovery shares provided by the other members.
 * 
 * @param shares A list of aggregated recovery shares.
 * @param idx    The index of the recovered share.
 * @returns      The recovered share.
 */
export function recover_share (
  shares : SecretShare[],
  idx    : number
) : SecretShare {
  const coeffs = shares.map(e => Buff.hex(e.seckey).big)
  const summed = coeffs.reduce((p, n) => mod_n(p + n), _0n)
  return { idx, seckey: Buff.big(summed).hex }
}

export function verify_recovery_share () {

}
