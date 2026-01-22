import { secp256k1 } from '@noble/curves/secp256k1.js'
import { Field }     from '@noble/curves/abstract/modular.js'

// Optimizes use of bigints as constants.
export const _0n = BigInt(0)
export const _1n = BigInt(1)

// Constants for the secp256k1 curve.
export const _P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f')
export const _N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

// Base constants for the secp256k1 curve.
export const FIELD = Field(_N)
export const POINT = secp256k1.Point

// Context string for this cryptography domain.
export const DOMAIN = 'FROST-secp256k1-SHA256-v1'

// Domain Separation Tag suffixes for FROST hash functions.
export const DST = {
  RHO:   'rho',
  CHAL:  'chal',
  NONCE: 'nonce',
  MSG:   'msg',
  COM:   'com'
} as const

export default { _0n, _1n, _N, _P, DOMAIN, DST, FIELD, POINT }
