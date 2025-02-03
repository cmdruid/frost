// As specified in draft-irtf-cfrg-frost-15, section 6.5.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-frostsecp256k1-sha-256

import { Buff }         from '@cmdcode/buff'
import { sha256 }       from '@noble/hashes/sha256'
import { DOMAIN, _N }   from '@/const.js'
import { str_to_bytes } from './util.js'

import { hash_to_field, Opts } from '@noble/curves/abstract/hash-to-curve'

const OPT = { m: 1, p: _N, k: 128, expand: 'xmd', hash: sha256 }

function get_opts (DST : string) {
  return { ...OPT, DST } as Opts
}

export function H1 (msg : Uint8Array) {
  const DST  = DOMAIN + 'rho'
  const nums = hash_to_field(msg, 1, get_opts(DST))
  return Buff.big(nums[0][0], 32)
}

export function H2 (msg : Uint8Array) {
  const DST  = DOMAIN + 'chal'
  const nums = hash_to_field(msg, 1, get_opts(DST))
  return Buff.big(nums[0][0], 32)
}

export function H3 (msg : Uint8Array) {
  const DST  = DOMAIN + 'nonce'
  const nums = hash_to_field(msg, 1, get_opts(DST))
  return Buff.big(nums[0][0], 32)
}

export function H4 (msg : Uint8Array) {
  const DST  = str_to_bytes(DOMAIN + 'msg')
  const hash = sha256(new Uint8Array([ ...DST, ...msg ]))
  return new Buff(hash)
}

export function H5 (msg : Uint8Array) {
  const DST  = str_to_bytes(DOMAIN + 'com')
  const hash = sha256(new Uint8Array([ ...DST, ...msg ]))
  return new Buff(hash)
}
