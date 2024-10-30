import { Buff, Bytes } from '@cmdcode/buff'
import { G }           from '@/ecc/index.js'

import type {
  BinderPackage,
  PublicNoncePackage
} from '@/types/index.js'

export function get_pubkey(secret : Bytes) {
  const scalar = Buff.bytes(secret).big
  const point  = G.ScalarBaseMulti(scalar)
  return G.SerializeElement(point).hex
}

export function get_group_commit (
  pnonces : PublicNoncePackage[]
) {
  let enc_group_commit : Bytes[] = []
  for (const { idx, hidden_pn, binder_pn } of pnonces) {
    const enc_commit = [ G.SerializeScalar(idx), hidden_pn, binder_pn ]
    enc_group_commit = [ ...enc_group_commit, ...enc_commit ]
  }
  return Buff.join(enc_group_commit)
}

export function get_nonce_ids (
  pnonces : PublicNoncePackage[]
) : bigint[] {
  return pnonces.map(pn => BigInt(pn.idx))
}

export function get_bind_factor (
  binders : BinderPackage[],
  idx     : number
) : bigint {
  for (const binder of binders) {
    if (idx === binder.idx) {
      return Buff.bytes(binder.bind_hash).big
    }
  }
  throw new Error('invalid participant')
}
