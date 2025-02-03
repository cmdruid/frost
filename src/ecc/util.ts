import { Buff, Bytes } from '@cmdcode/buff'
import { mod, pow }    from '@noble/curves/abstract/modular'

import CONST from '@/const.js'

const { POINT, _N, _P } = CONST

export function mod_n (x : bigint) {
  return mod(x, _N)
}

export function mod_p (x : bigint) {
  return mod(x, _P)
}

export function pow_n (x : number | bigint, p : number | bigint) {
  if (typeof x === 'number') x = BigInt(x)
  if (typeof p === 'number') p = BigInt(p)
  return pow(x, p, _N)
}

export function str_to_bytes (str : string) {
  return new TextEncoder().encode(str)
}

export function bytes_to_str (bytes : Uint8Array) {
  return new TextDecoder().decode(bytes)
}

export function lift_x (pubkey : Bytes) {
  let bytes = Buff.bytes(pubkey)
  if (bytes.length < 32 || bytes.length > 33) {
    throw new Error('invalid pubkeky: ' + bytes.hex + ' ' + bytes.length)
  } else if (bytes.length === 32) {
    bytes = bytes.prepend(2)
  }
  return POINT.fromHex(bytes.hex)
}
