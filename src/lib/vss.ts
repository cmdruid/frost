/**
 * @fileoverview Verifiable Secret Sharing (VSS) Operations
 *
 * Implements VSS commitments that allow participants to verify their
 * shares without revealing the secret. The polynomial coefficients
 * are committed to via their public keys (coefficient * G).
 */

import { Buff, Bytes }   from '@vbyte/buff'
import { G }             from '@/ecc/index.js'
import { assert }        from '@/util/index.js'
import { mod_n, lift_x } from '@/ecc/util.js'

/**
 * Creates polynomial coefficients for Shamir Secret Sharing.
 *
 * Generates `threshold` coefficients where the first coefficient (a_0)
 * is the secret being shared. The polynomial is:
 * f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
 *
 * For deterministic results (e.g., in testing), provide all coefficients
 * via the secrets array. Otherwise, random coefficients are generated.
 *
 * @param secrets - Optional array of pre-determined 32-byte coefficients
 * @param threshold - The number of coefficients to generate (polynomial degree + 1)
 * @returns Array of coefficient bigints reduced mod N
 */
export function create_share_coeffs (
  secrets   : Bytes[],
  threshold : number,
) {
  if (threshold < 1) {
    throw new Error('threshold must be at least 1')
  }
  const coeffs : bigint[] = []
  for (let i = 0; i < threshold; i++) {
    const secret = secrets.at(i)
    const coeff  = (secret !== undefined)
      ? Buff.bytes(secret).big
      : Buff.random(32).big
    coeffs.push(mod_n(coeff))
  }
  return coeffs
}

/**
 * Creates VSS commitments for polynomial coefficients.
 *
 * Each commitment is the public key corresponding to a coefficient:
 * C_i = a_i * G
 *
 * The first commitment (C_0) is the group public key corresponding
 * to the shared secret.
 *
 * @param share_coeffs - Array of polynomial coefficients (as bigints)
 * @returns Array of 33-byte compressed public key commitments (hex)
 */
export function get_share_commits (
  share_coeffs : bigint[]
) : string[] {
  return share_coeffs.map(e => {
    return G.ScalarBaseMulti(e).toHex(true)
  })
}

/**
 * Merges two arrays of VSS commitments by point addition.
 *
 * Used in DKG to combine commitments from multiple dealers. The merged
 * commitments verify shares from the combined polynomial.
 *
 * @param commits_a - First array of commitments
 * @param commits_b - Second array of commitments (must have same length)
 * @returns Array of merged commitments
 * @throws Error if arrays have different sizes
 */
export function merge_share_commits (
  commits_a : string[],
  commits_b : string[]
) : string[] {
  assert.equal_arr_size(commits_a, commits_b)
  const commits : string[] = []
  for (let i = 0; i < commits_a.length; i++) {
    const point_a = lift_x(commits_a[i])
    const point_b = lift_x(commits_b[i])
    const point_c = G.ElementAdd(point_a, point_b)
    const commit  = G.SerializeElement(point_c)
    commits.push(commit.hex)
  }
  return commits
}
