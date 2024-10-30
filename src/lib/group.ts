import { Bytes }         from '@cmdcode/buff'
import { _0n, _1n }      from '@/const.js'
import { assert }        from '@/util/index.js'
import { create_coeffs } from './poly.js'

import {
  create_shares,
  get_coeff_commits,
  merge_coeff_commits,
  merge_shares
} from './shares.js'

import type { ShareGroup } from '@/types/index.js'

export function create_share_group (
  secrets   : Bytes[],
  threshold : number,
  share_max : number,
) : ShareGroup {
  // Create the coefficients for the polynomial.
  const coeffs  = create_coeffs(secrets, threshold)
  // Create the secret shares for each member.
  const shares  = create_shares(coeffs, share_max)
  // Create the commitments for each share.
  const commits = get_coeff_commits(coeffs)
  // Get the group pubkey for the shares.
  const pubkey  = commits[0]
  // Return the share package object.
  return { commits, pubkey, shares }
}

// export function merge_share_groups (
//   group_a : ShareGroup,
//   group_b : ShareGroup
// ) : ShareGroup {
//   // Merge the shares.
//   const shares  = merge_shares(group_a.shares, group_b.shares)
//   // Merge the commits.
//   const commits = merge_coeff_commits(group_a.commits, group_b.commits)
//   // Define the group public key.
//   const pubkey = group_a.pubkey
//   // Return the merged group.
//   return { commits, pubkey, shares }
// }

export function refresh_share_group (
  group   : ShareGroup,
  secrets : Bytes[] = []
) : ShareGroup {
  const share_max = group.shares.length
  const threshold = group.commits.length
  // Create the auxiliary coefficients used to update the shares.
  const aux_coeffs  = create_coeffs(secrets, threshold - 1)
  // Create the commitments for each auxiliary coefficient.
  const aux_commits = get_coeff_commits(aux_coeffs)
  // Remove the first commit (group pubkey) from the group commits.
  const sub_commits = group.commits.slice(1)
  // Merge the sub commits and auxiliary commits.
  const agg_commits = merge_coeff_commits(sub_commits, aux_commits)
  // Prepend a zero value to the list of auxiliary coefficients.
  const ref_coeffs = [ _0n, ...aux_coeffs ]
  // Create the auxiliary shares for updating each share.
  const ref_shares = create_shares(ref_coeffs, share_max)
  // Merge the group shares and auxiliary shares.
  const shares  = merge_shares(group.shares, ref_shares)
  // Define the group public key.
  const pubkey  = group.pubkey
  // Prepend the first commit (group pubkey) into the merged commit list.
  const commits = [ pubkey, ...agg_commits ]
  // Return the merged group data.
  return { commits, pubkey, shares }
}

export function repair_share_group () {
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