import { mod, pow } from '@noble/curves/abstract/modular'

import CONST from './const.js'

const { curve } = CONST

export function mod_n (x : bigint) {
  return mod(x, curve.n)
}

export function mod_p (x : bigint) {
  return mod(x, curve.p)
}

export function pow_n (x : number | bigint, p : number | bigint) {
  if (typeof x === 'number') x = BigInt(x)
  if (typeof p === 'number') p = BigInt(p)
  return pow(x, p, curve.n)
}

export function str_to_bytes (str : string) {
  return new TextEncoder().encode(str)
}

export function bytes_to_str (bytes : Uint8Array) {
  return new TextDecoder().decode(bytes)
}
