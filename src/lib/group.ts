import { Bytes }    from '@cmdcode/buff'
import { _0n, _1n } from '@/const.js'

import {
  create_shares
} from './shares.js'

import {
  create_share_coeffs,
  get_share_commits
} from './vss.js'

import type { SecretShareSet, DealerShareSet } from '@/types/index.js'

export function create_share_set (
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : SecretShareSet {
  // Create the coefficients for the polynomial.
  const coeffs      = create_share_coeffs(secrets, threshold)
  // Create the secret shares for each member.
  const shares      = create_shares(coeffs, share_max)
  // Create the commitments for each share.
  const vss_commits = get_share_commits(coeffs)
  // Return the share package object.
  return { shares, vss_commits }
}

export function create_dealer_set (
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : DealerShareSet {
  const share_set = create_share_set(threshold, share_max, secrets) 
  const group_pk  = share_set.vss_commits[0]
  // Return the share package object.
  return { ...share_set, group_pk }
}
