import { Buff, Bytes } from '@cmdcode/buff'
import { G }           from './ecc/index.js'
import { Point }       from './ecc/const.js'

import { NonceBinder, PublicNonce } from './types.js'

export function random_bytes (size = 32) {
  return Buff.random(size)
}

export function count_scalars (x_j : bigint, L : bigint[]) {
  return L.filter(x => x === x_j).length
}

export function get_record<T extends { idx : number }> (
  records : T[],
  index   : number
) {
  const record = records.find(e => e.idx === index)
  if (record === undefined) {
    throw new Error('record not found for index: ' + index)
  }
  return record
}

export function get_pubkey(secret : Bytes) {
  const scalar = Buff.bytes(secret).big
  const point  = G.ScalarBaseMulti(scalar)
  return G.SerializeElement(point).hex
}

export function encode_group_commit_list (
  pub_nonces : PublicNonce[]
) {
  let enc_group_commit : Bytes[] = []
  for (const { idx, pnonce_h, pnonce_b } of pub_nonces) {
    const enc_commit = [ G.SerializeScalar(idx), pnonce_h, pnonce_b ]
    enc_group_commit = [ ...enc_group_commit, ...enc_commit ]
  }
  return Buff.join(enc_group_commit)
}

export function get_nonce_identifiers (
  pub_nonces : PublicNonce[]
) : bigint[] {
  return pub_nonces.map(pn => BigInt(pn.idx))
}

export function get_bind_factor (
  binders : NonceBinder[],
  idx     : number
) : bigint {
  for (const binder of binders) {
    if (idx === binder.idx) {
      return Buff.bytes(binder.key).big
    }
  }
  throw new Error('invalid participant')
}

export function lift_x (pubkey : Bytes) {
  let bytes = Buff.bytes(pubkey)
  if (bytes.length < 32 || bytes.length > 33) {
    throw new Error('invalid pubkeky: ' + bytes.hex + ' ' + bytes.length)
  } else if (bytes.length === 32) {
    bytes = bytes.prepend(2)
  }
  return Point.fromHex(bytes.hex)
}
