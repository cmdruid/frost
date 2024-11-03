import { Buff }                from '@cmdcode/buff'
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

export function create_ecdh_share (
  members : number[],
  share   : SecretShare,
  pubkey  : string
) : PublicShare {
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

export function derive_ecdh_secret (
  shares : PublicShare[]
) {
  let point : CurveElement | null = null
  for (const share of shares) {
    if (point === null) {
      point = lift_x(share.pubkey)
    } else {
      const pt = lift_x(share.pubkey)
      point = point.add(pt)
    }
  }
  assert.exists(point)
  return G.SerializeElement(point).hex
}
