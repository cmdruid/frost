import { Buff, Bytes } from '@cmdcode/buff'
import { G }           from '@/ecc/index.js'
import { _0n, _1n }    from '@/ecc/const.js'
import { assert }      from '@/util/index.js'

import { mod_n, pow_n, lift_x } from '@/ecc/util.js'

import {
  create_coeffs,
  interpolate_root,
  evaluate_x
} from './poly.js'

import type {
  SecretShare,
  SharePackage
} from '@/types/index.js'

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

export function derive_share (
  shares : SecretShare[]
) : SecretShare {
  // Check that each share has the same idx.
  assert.is_equal_set(shares.map(e => e.idx))
  // Get the index value of the first share.
  const idx    = shares[0].idx
  // Sum all secret shares into a DKG secret.
  const secret = shares
    .map(e => Buff.bytes(e.seckey).big)
    .reduce((acc, cur) => acc += cur, _0n)
  // Format group share into a secret key.
  const seckey = Buff.big(mod_n(secret), 32).hex
  // Return secret as a share package.
  return { idx, seckey }
}

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

/**
 * Combine secret shares and reconstruct the root secret.
 */
export function combine_shares (shares : SecretShare[]) {
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
