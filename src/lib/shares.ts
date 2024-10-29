import { Buff, Bytes } from '@cmdcode/buff'
import { G }           from '@/ecc/index.js'
import { _0n, _1n }    from '@/const.js'
import { assert, get_record }      from '@/util/index.js'

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

export function combine_shares (
  shares : SecretShare[]
) : SecretShare {
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

/**
 * Updates a list of secret shares for a given polynomial.
 */
export function update_shares (
  curr_shares : SecretShare[],
  aux_shares  : SecretShare[]
) : SecretShare[] {
  // Init our share list.
  const shares = []
  // For each share to generate (skipping the root):
  for (let i = 0; i <= curr_shares.length; i++) {
    const curr_share = curr_shares[i]
    const aux_share  = get_record(aux_shares, curr_share.idx)
    const new_share  = combine_shares([ curr_share, aux_share ])
    shares.push(new_share)
  }
  // Return the list of shares.
  return shares
}

/**
 * Create a list of public key commitments, one for each coefficient.
 */
export function get_coeff_commits (coeffs : Bytes[]) : string[] {
  // For each coefficient in the list:
  return coeffs.map(e => {
    // Convert to a scalar value.
    const scalar = Buff.bytes(e).big
    // Return the generator point value, in hex.
    return G.ScalarBaseMulti(scalar).toHex(true)
  })
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
