/**
 * @fileoverview Elliptic Curve Type Definitions
 *
 * Types for elliptic curve elements and point state used in
 * FROST cryptographic operations.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'

/**
 * An elliptic curve point on secp256k1 in projective coordinates.
 *
 * This is a point type from the @noble/curves library representing
 * a point on the secp256k1 curve used in Bitcoin.
 */
export type CurveElement = InstanceType<typeof secp256k1.Point>

/**
 * Check if a curve element has an even y-coordinate.
 *
 * Note: hasEvenY exists at runtime in @noble/curves but is missing from
 * the v2 type definitions. This helper provides type-safe access.
 */
export function hasEvenY (point: CurveElement): boolean {
  return (point as CurveElement & { hasEvenY(): boolean }).hasEvenY()
}

/**
 * Point state for BIP340/Taproot parity tracking.
 *
 * When applying Taproot-style tweaks to a point, the y-coordinate parity
 * may change at each step. This state tracks the accumulated parity so
 * that signing operations can correctly adjust secret shares.
 *
 * @property parity - The current parity factor (+1 or -1 mod N) for the final point
 * @property point - The final tweaked curve element
 * @property state - The accumulated parity factor from all tweak applications
 * @property tweak - The accumulated tweak value (adjusted for negations)
 */
export interface PointState {
  /** The current parity factor (+1n or N-1n) for the final point */
  parity : bigint
  /** The final tweaked curve element */
  point  : CurveElement
  /** The accumulated parity factor from all tweak applications */
  state  : bigint
  /** The accumulated tweak value (adjusted for negations) */
  tweak  : bigint
}
