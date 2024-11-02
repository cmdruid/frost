import { Bytes }    from '@cmdcode/buff'
import { _0n, _1n } from '@/const.js'

import {
  create_shares
} from './shares.js'

import {
  create_coeffs,
  get_coeff_commits
} from './vss.js'

import type { ShareGroup, KeyGroup } from '@/types/index.js'

export function create_share_group (
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : ShareGroup {
  // Create the coefficients for the polynomial.
  const coeffs  = create_coeffs(secrets, threshold)
  // Create the secret shares for each member.
  const shares  = create_shares(coeffs, share_max)
  // Create the commitments for each share.
  const commits = get_coeff_commits(coeffs)
  // Return the share package object.
  return { commits, shares }
}

export function create_key_group (
  threshold : number,
  share_max : number,
  secrets   : Bytes[] = []
) : KeyGroup {
  const share_set = create_share_group(threshold, share_max, secrets) 
  const pubkey    = share_set.commits[0]
  // Return the share package object.
  return { ...share_set, pubkey }
}
