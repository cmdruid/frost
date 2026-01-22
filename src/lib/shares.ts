/**
 * @fileoverview FROST Secret Share Management
 *
 * Implements Shamir Secret Sharing operations for creating, combining,
 * and verifying threshold secret shares. Shares are evaluated at indices
 * 1, 2, 3, ... (never at 0, which would reveal the secret).
 */

import { Buff, Bytes }          from '@vbyte/buff'
import { G }                    from '@/ecc/index.js'
import { _0n }                  from '@/const.js'
import { assert, get_record }   from '@/util/index.js'
import { mod_n, pow_n, lift_x } from '@/ecc/util.js'

import {
  interpolate_root,
  evaluate_x
} from './poly.js'

import type { SecretShare } from '@/types/index.js'

/**
 * Creates secret shares by evaluating a polynomial at consecutive indices.
 *
 * Evaluates the polynomial at x = 1, 2, ..., count to produce secret shares.
 * The polynomial's constant term (coeffs[0]) is the secret being shared.
 *
 * @note Shares are 1-indexed: indices start at 1, not 0. Index 0 corresponds
 *       to the secret itself and is never used as a share index.
 *
 * @param coeffs - Polynomial coefficients [a_0, a_1, ..., a_{t-1}] where a_0 is the secret
 * @param count - Number of shares to generate
 * @returns Array of secret shares with indices 1 through count
 */
export function create_shares (
  coeffs : bigint[],
  count  : number
) : SecretShare[] {
  if (coeffs.length === 0) {
    throw new Error('coeffs array cannot be empty')
  }
  if (count < 1) {
    throw new Error('count must be at least 1')
  }
  // Init our share list.
  const shares  = []
  // For each share to generate (skipping the root):
  for (let i = 1; i < count + 1; i++) {
    // Evaluate the polynomial at the index (i).
    const scalar = evaluate_x(coeffs, BigInt(i))
    // Mod and convert the scalar into a hex value.
    const seckey = Buff.big(scalar, 32).hex
    // Add the index and share.
    shares.push({ idx: i, seckey })
  }
  // Return the list of shares.
  return shares
}

/**
 * Retrieves a share by its index from an array of shares.
 *
 * @param shares - Array of secret shares
 * @param index - The 1-based index of the share to retrieve
 * @returns The share at the specified index
 * @throws Error if no share exists at the given index
 */
export function get_share (
  shares : SecretShare[],
  index  : number
) {
  return get_record(shares, index)
}

/**
 * Combines multiple secret shares by addition.
 *
 * Used in DKG (Distributed Key Generation) to aggregate contributions
 * from multiple dealers into a single share. This is NOT Lagrange
 * interpolation - it's simple scalar addition.
 *
 * @param shares - Array of shares to combine (typically from different dealers)
 * @returns The combined secret key as a 32-byte hex string
 */
export function combine_shares (
  shares : SecretShare[]
) : string {
  const secret = shares
    .map(e => Buff.bytes(e.seckey).big)
    .reduce((acc, cur) => mod_n(acc + cur), _0n)
  return Buff.big(secret, 32).hex
}

/**
 * Combines shares with the same index from multiple sources.
 *
 * Validates that all shares have the same index, then combines them.
 * Used when aggregating DKG contributions for a single participant.
 *
 * @param shares - Array of shares (must all have the same idx)
 * @returns A single combined share
 * @throws Error if shares have different indices
 */
export function combine_set (
  shares : SecretShare[]
) : SecretShare {
  if (shares.length === 0) {
    throw new Error('shares array cannot be empty')
  }
  assert.is_equal_set(shares.map(e => e.idx))
  const idx    = shares[0].idx
  const seckey = combine_shares(shares)
  return { idx, seckey }
}

/**
 * Merges two arrays of secret shares pairwise by index.
 *
 * For each share in shares_a, finds the corresponding share in shares_b
 * (by matching idx) and combines them. Used in DKG to merge contributions.
 *
 * @param shares_a - First array of shares
 * @param shares_b - Second array of shares (must have same length)
 * @returns Array of merged shares
 * @throws Error if arrays have different sizes
 */
export function merge_shares (
  shares_a : SecretShare[],
  shares_b : SecretShare[]
) : SecretShare[] {
  assert.equal_arr_size(shares_a, shares_b)
  const shares = []
  for (let i = 0; i < shares_a.length; i++) {
    const curr_share = shares_a[i]
    const aux_share  = get_record(shares_b, curr_share.idx)
    const agg_share  = combine_set([ curr_share, aux_share ])
    shares.push(agg_share)
  }
  return shares
}

/**
 * Verifies a secret share against VSS (Verifiable Secret Sharing) commitments.
 *
 * Uses the VSS polynomial commitments to verify that a share is correctly
 * derived from the expected polynomial. This allows verification without
 * revealing the secret or other shares.
 *
 * Verification equation: share_i * G == sum(commit_j * idx^j) for j in 0..t-1
 *
 * @param commits - Array of VSS commitments (public keys) for the polynomial
 * @param share - The secret share to verify
 * @param thold - The threshold value (number of commitments to use)
 * @returns True if the share is valid, false otherwise
 */
export function verify_share (
  commits : Bytes[],
  share   : SecretShare,
  thold   : number
) {
  const scalar = Buff.bytes(share.seckey).big
  const S_i    = G.ScalarBaseMulti(scalar) 
  let   S_ip   = null
  for (let j = 0; j < thold; j++) {
    const point  = lift_x(commits[j])
    const scalar = pow_n(share.idx, j)
    const prod   = G.ScalarMulti(point, scalar)
    S_ip = G.ElementAdd(S_ip, prod)
  }
  assert.exists(S_ip)
  return S_i.x === S_ip.x
}

/**
 * Reconstructs the root secret from threshold shares using Lagrange interpolation.
 *
 * Given at least threshold shares, interpolates the polynomial and evaluates
 * at x=0 to recover the original secret. This is the inverse operation of
 * `create_shares`.
 *
 * @security This function reveals the root secret. It should only be used
 *           in testing or when key recovery is explicitly required.
 *
 * @param shares - Array of secret shares (must have at least threshold shares)
 * @returns The reconstructed secret as a 32-byte hex string
 */
export function derive_shares_secret (
  shares : SecretShare[]
) : string {
  const coords = shares.map(share => [
    BigInt(share.idx),
    Buff.bytes(share.seckey).big
  ])
  const secret = interpolate_root(coords)
  return Buff.big(secret).hex
}
