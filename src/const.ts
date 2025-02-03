import { secp256k1 } from '@noble/curves/secp256k1'
import { Field }     from '@noble/curves/abstract/modular'

// Optimizes use of bigints as constants.
export const _0n = BigInt(0)
export const _1n = BigInt(1)

// Constants for the secp256k1 curve.
export const _P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f')
export const _N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

// Base constants for the secp256k1 curve.
export const CURVE = secp256k1.CURVE
export const FIELD = Field(_N, 32, true)
export const POINT = secp256k1.ProjectivePoint

// Context string for this cryptography domain.
export const DOMAIN = 'FROST-secp256k1-SHA256-v1'

export default { _0n, _1n, _N, _P, CURVE, DOMAIN, FIELD, POINT }
