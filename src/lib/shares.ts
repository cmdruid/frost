import { Buff, Bytes }          from '@cmdcode/buff'
import { G }                    from '@/ecc/index.js'
import { _0n, _1n }             from '@/const.js'
import { assert, get_record }   from '@/util/index.js'
import { mod_n, pow_n, lift_x } from '@/ecc/util.js'

import {
  interpolate_root,
  evaluate_x
} from './poly.js'

import type { SecretShare } from '@/types/index.js'

/**
 * Creates a list of secret shares for a given polynomial.
 */
export function create_shares (
  coeffs : bigint[],
  count  : number
) : SecretShare[] {
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

export function get_share (
  shares : SecretShare[],
  index  : number 
) {
  // Return share at index.
  return get_record(shares, index)
}

export function combine_shares (
  shares : SecretShare[]
) : string {
  // Sum all secret shares into a DKG secret.
  const secret = shares
    .map(e => Buff.bytes(e.seckey).big)
    .reduce((acc, cur) => mod_n(acc += cur), _0n)
  // Format group share into a secret key.
  return Buff.big(secret, 32).hex
}

export function combine_set (
  shares : SecretShare[]
) : SecretShare {
  // Check that each share has the same idx.
  assert.is_equal_set(shares.map(e => e.idx))
  // Get the index value of the first share.
  const idx    = shares[0].idx
  // Get the combined secret key.
  const seckey = combine_shares(shares)
  // Return secret as a share package.
  return { idx, seckey }
}

/**
 * Merge a list of secret shares for a given polynomial.
 */
export function merge_shares (
  shares_a : SecretShare[],
  shares_b : SecretShare[]
) : SecretShare[] {
  assert.equal_arr_size(shares_a, shares_b)
  // Init our share list.
  const shares = []
  // For each share to generate (skipping the root):
  for (let i = 0; i < shares_a.length; i++) {
    const curr_share = shares_a[i]
    const aux_share  = get_record(shares_b, curr_share.idx)
    const agg_share  = combine_set([ curr_share, aux_share ])
    shares.push(agg_share)
  }
  // Return the list of shares.
  return shares
}

/**
 * Verify a secret share using a list of vss commitments.
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


// export function create_share_set (
//   shares : SecretShare[],
//   index  : number
// ) : SecretShareSet {
//   return { idx : index, shares }
// }

/**
 * Interpolate secret shares and derive the root secret.
 */
export function derive_shares_secret (
  shares : SecretShare[]
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
