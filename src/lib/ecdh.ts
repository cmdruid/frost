/**
 * @fileoverview Threshold ECDH (Elliptic Curve Diffie-Hellman)
 *
 * Implements threshold ECDH where participants collaboratively compute
 * a shared secret with an external public key, without any single
 * participant learning the group's secret key.
 */

import { Buff }                from '@vbyte/buff'
import { lift_x, mod_n }       from '@/ecc/util.js'
import { G }                   from '@/ecc/index.js'
import { assert }              from '@/util/index.js'
import { _0n }                 from '@/const.js'
import { calc_lagrange_coeff } from './poly.js'

import type {
  CurveElement,
  PublicShare,
  SecretShare
} from '@/types/index.js'

/**
 * Creates an ECDH share for threshold key agreement.
 *
 * Each participant computes their contribution to the ECDH shared secret
 * using their secret share and the Lagrange coefficient. The contributions
 * are later combined to produce the full shared secret.
 *
 * The computation is: lambda_i * s_i * P, where:
 * - lambda_i is the Lagrange coefficient for participant i
 * - s_i is participant i's secret share
 * - P is the external public key
 *
 * @param members - Array of participant indices in the ECDH operation
 * @param share - The participant's secret share
 * @param pubkey - The external public key to perform ECDH with
 * @returns A public share containing the ECDH contribution
 */
export function create_ecdh_share (
  members : number[],
  share   : SecretShare,
  pubkey  : string
) : PublicShare {
  if (!members.includes(share.idx)) {
    throw new Error('share index must be in members array')
  }
  const mbrs = members
    .filter(idx => idx !== share.idx)
    .map(i => BigInt(i))
  const idx     = BigInt(share.idx)
  const secret  = Buff.hex(share.seckey).big
  const point   = lift_x(pubkey)
  const L_coeff = calc_lagrange_coeff(mbrs, idx, _0n)
  const P_coeff = mod_n(L_coeff * secret)
  const ecdh_pt = point.multiply(P_coeff)
  const ecdh_pk = G.SerializeElement(ecdh_pt).hex
  return { idx: share.idx, pubkey: ecdh_pk }
}

/**
 * Derives the final ECDH shared secret from participant contributions.
 *
 * Aggregates all ECDH shares by point addition to reconstruct the
 * full shared secret: secret * P = sum(lambda_i * s_i * P)
 *
 * @param shares - Array of ECDH contribution shares from threshold participants
 * @returns The shared secret as a 33-byte compressed public key (hex)
 */
export function derive_ecdh_secret (
  shares : PublicShare[]
) {
  let point : CurveElement | null = null
  for (const share of shares) {
    const pt = lift_x(share.pubkey)
    point = G.ElementAdd(point, pt)
  }
  assert.exists(point)
  return G.SerializeElement(point).hex
}
