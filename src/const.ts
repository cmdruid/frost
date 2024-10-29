import { secp256k1 } from '@noble/curves/secp256k1'
import { Field }     from '@noble/curves/abstract/modular'

// Optimizes use of bigints as constants.
export const _0n = BigInt(0)
export const _1n = BigInt(1)

// Base constants for the secp256k1 curve.
export const curve = secp256k1.CURVE
export const field = Field(curve.n, 32, true)
export const Point = secp256k1.ProjectivePoint

// Context string for this cryptography domain.
export const ctx_str = 'FROST-secp256k1-SHA256-v1'

export default { _0n, _1n, curve, ctx_str, field, Point }
