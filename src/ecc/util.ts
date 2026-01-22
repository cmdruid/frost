/**
 * @fileoverview Elliptic Curve Utility Functions
 *
 * Provides low-level utilities for modular arithmetic and data conversion
 * used throughout the FROST implementation. These functions handle
 * operations in both the curve order (N) and field prime (P).
 */

import { Buff, Bytes } from '@vbyte/buff'
import { mod, pow }    from '@noble/curves/abstract/modular.js'

import CONST from '@/const.js'

const { POINT, _N, _P } = CONST

/**
 * Computes x modulo the curve order N.
 *
 * All scalar operations in FROST must be performed modulo N to ensure
 * values remain valid scalars in the group.
 *
 * @param x - The value to reduce
 * @returns x mod N (always positive)
 */
export function mod_n (x : bigint) {
  return mod(x, _N)
}

/**
 * Computes x modulo the field prime P.
 *
 * Used for field operations when computing y-coordinates or
 * checking point validity.
 *
 * @param x - The value to reduce
 * @returns x mod P (always positive)
 */
export function mod_p (x : bigint) {
  return mod(x, _P)
}

/**
 * Computes modular exponentiation: x^p mod N.
 *
 * Used in polynomial evaluation and Lagrange coefficient computation.
 * Accepts both number and bigint inputs for convenience.
 *
 * @param x - The base value
 * @param p - The exponent
 * @returns x^p mod N
 */
export function pow_n (x : number | bigint, p : number | bigint) {
  if (typeof x === 'number') x = BigInt(x)
  if (typeof p === 'number') p = BigInt(p)
  return pow(x, p, _N)
}

/**
 * Converts a string to UTF-8 encoded bytes.
 *
 * Used for encoding domain separation tags and other string data.
 *
 * @param str - The string to encode
 * @returns UTF-8 encoded Uint8Array
 */
export function str_to_bytes (str : string) {
  return new TextEncoder().encode(str)
}

/**
 * Lifts an x-coordinate to a curve point (BIP340 x-only pubkey handling).
 *
 * Converts a 32-byte x-only public key (BIP340 format) or 33-byte compressed
 * public key to a full curve point. For x-only keys, assumes even y-coordinate.
 *
 * This is essential for BIP340/Taproot compatibility where public keys are
 * represented as 32-byte x-coordinates only.
 *
 * @param pubkey - Either 32-byte x-only or 33-byte compressed public key
 * @returns The corresponding curve point
 * @throws Error if pubkey length is not 32 or 33 bytes
 */
export function lift_x (pubkey : Bytes) {
  let bytes = Buff.bytes(pubkey)
  if (bytes.length < 32 || bytes.length > 33) {
    throw new Error(`invalid pubkey length: expected 32 or 33 bytes, got ${bytes.length}`)
  } else if (bytes.length === 32) {
    bytes = bytes.prepend(2)
  }
  return POINT.fromHex(bytes.hex)
}
