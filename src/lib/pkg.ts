import { Bytes }         from '@cmdcode/buff'
import { _0n, _1n }      from '@/const.js'
import { assert }        from '@/util/index.js'
import { create_coeffs } from './poly.js'

import {
  create_shares,
  get_coeff_commits
} from './shares.js'

import type { SecretShare, SharePackage } from '@/types/index.js'

export function create_share_pkg (
  secrets   : Bytes[],
  threshold : number,
  share_max : number,
) : SharePackage {
  // Create the coefficients for the polynomial.
  const coeffs       = create_coeffs(secrets, threshold)
  // Create the secret shares for each member.
  const sec_shares   = create_shares(coeffs, share_max)
  // Create the commitments for each share.
  const vss_commits  = get_coeff_commits(coeffs)
  // Get the group pubkey for the shares.
  const group_pubkey = vss_commits[0]
  // Return the share package object.
  return { group_pubkey, sec_shares, vss_commits }
}

export function repair_share_pkg () {
  // Generate from each share.
  // Aggregate from each share.
  // Combine aggregate share to get missing share.
}

// export function update_share_pkg (
//   group_pk  : Bytes,
//   secrets   : Bytes[],
//   shares    : SecretShare[],
//   share_ct  : number,
//   threshold : number
// ) : SharePackage {
//   // For now, we must throw if we don't have all shares.
//   assert.ok(shares.length >= threshold, 'not enough shares to make update')
//   assert.ok(shares.length = share_ct)
//   // Ensure the first secret is zero.
//   secrets   = [ '00'.repeat(32), ...secrets ]
//   // Create a new share package.
//   const pkg = create_share_pkg(secrets, threshold, share_ct)
//   // Update each share with the new package.
  

//   // Return the share package object.
//   return { group_pubkey, sec_shares, vss_commits }
// }