import { Buff, Bytes } from '@cmdcode/buff'
import { G }           from '@/ecc/index.js'
import { _0n, _1n }    from '@/const.js'

import { assert, get_record }   from '@/util/index.js'
import { mod_n, pow_n, lift_x } from '@/ecc/util.js'

import {
  interpolate_root,
  evaluate_x
} from './poly.js'

import type { SharePackage } from '@/types/index.js'

/**
 * Creates a list of secret shares for a given polynomial.
 */
export function create_shares (
  coeffs : bigint[],
  count  : number
) : SharePackage[] {
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

export function combine_shares (
  shares : SharePackage[]
) : SharePackage {
  // Check that each share has the same idx.
  assert.is_equal_set(shares.map(e => e.idx))
  // Get the index value of the first share.
  const idx    = shares[0].idx
  // Sum all secret shares into a DKG secret.
  const secret = shares
    .map(e => Buff.bytes(e.seckey).big)
    .reduce((acc, cur) => mod_n(acc += cur), _0n)
  // Format group share into a secret key.
  const seckey = Buff.big(secret, 32).hex
  // Return secret as a share package.
  return { idx, seckey }
}

/**
 * Interpolate secret shares and derive the root secret.
 */
export function derive_secret (
  shares : SharePackage[]
) : string {
  // Convert each share into coordinates.
  const coords = shares.map(share => [
    BigInt(share.idx),
    Buff.bytes(share.seckey).big
  ])
  // Interpolate the coordinates to recreate the secret.
  const secret = interpolate_root(coords)
  // Return the secret as hex.
  return Buff.big(secret).hex
}

/**
 * Merge a list of secret shares for a given polynomial.
 */
export function merge_shares (
  shares_a : SharePackage[],
  shares_b : SharePackage[]
) : SharePackage[] {
  assert.equal_arr_size(shares_a, shares_b)
  // Init our share list.
  const shares = []
  // For each share to generate (skipping the root):
  for (let i = 0; i < shares_a.length; i++) {
    const curr_share = shares_a[i]
    const aux_share  = get_record(shares_b, curr_share.idx)
    const agg_share  = combine_shares([ curr_share, aux_share ])
    shares.push(agg_share)
  }
  // Return the list of shares.
  return shares
}

/**
 * Create a list of public key commitments, one for each coefficient.
 */
export function get_coeff_commits (
  coeffs : Bytes[]
) : string[] {
  // For each coefficient in the list:
  return coeffs.map(e => {
    // Convert to a scalar value.
    const scalar = Buff.bytes(e).big
    // Return the generator point value, in hex.
    return G.ScalarBaseMulti(scalar).toHex(true)
  })
}

/**
 * Create a list of public key commitments, one for each coefficient.
 */
export function merge_coeff_commits (
  commits_a : string[],
  commits_b : string[]
) : string[] {
  assert.equal_arr_size(commits_a, commits_b)
  // Define an array of updated commits.
  const commits : string[] = []
  // For each commit in the list:
  for (let i = 0; i < commits_a.length; i++) {
    const point_a = lift_x(commits_a[i])
    const point_b = lift_x(commits_b[i])
    const point_c = G.ElementAdd(point_a, point_b)
    const commit  = G.SerializeElement(point_c)
    commits.push(commit.hex)
  }
  // Return the updated commits.
  return commits
}

/**
 * Verify a secret share using a list of vss commitments.
 */
export function verify_share (
  commits : Bytes[],
  share   : SharePackage,
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
