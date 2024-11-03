import { Bytes }    from '@cmdcode/buff'
import { _0n, _1n } from '@/const.js'

import {
  combine_set,
  create_shares
} from './shares.js'

import {
  create_coeffs,
  get_coeff_commits
} from './vss.js'

import type { SecretShare, SharePackage } from '@/types/index.js'

export function gen_refresh_shares (
  index     : number,
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : SharePackage {
  // Create the auxiliary coefficients used to update the shares.
  const sub_coeffs = create_coeffs(secrets, threshold - 1)
  // Prepend a zero value to the list of auxiliary coefficients.
  const coeffs  = [ _0n, ...sub_coeffs ]
  // Create the refresh shares used for updating the group.
  const shares  = create_shares(coeffs, share_max)
  // Prepend the first commit into the merged commit list.
  const commits = get_coeff_commits(sub_coeffs)
  // Return the merged share data.
  return { commits, idx: index, shares }
}

export function refresh_share (
  refresh_shares : SecretShare[],
  current_share  : SecretShare
) : SecretShare {
  const shares = [ current_share, ...refresh_shares ]
  return combine_set(shares)
}
