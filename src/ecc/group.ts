/**
 * @fileoverview Elliptic Curve Group Operations for secp256k1
 *
 * Implements the group operations specified in draft-irtf-cfrg-frost-15,
 * section 3.1 for the secp256k1 curve used in Bitcoin.
 *
 * @see https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html
 *
 * The secp256k1 curve has:
 * - Order N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * - Field prime P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 */

import { Buff, Bytes } from '@vbyte/buff'
import { secp256k1 }   from '@noble/curves/secp256k1.js'
import { assert }      from '@/util/index.js'

import type { CurveElement } from '@/types/index.js'

import CONST from '@/const.js'

const { POINT } = CONST

/**
 * Adds two elliptic curve points together.
 *
 * Implements the group addition operation A + B. Handles null values
 * gracefully, treating null as the identity element.
 *
 * @param A - First point (or null for identity)
 * @param B - Second point (or null for identity)
 * @returns The sum A + B as a CurveElement
 * @throws Error if both inputs are null
 */
export function ElementAdd (
  A : CurveElement | null,
  B : CurveElement | null
) : CurveElement {
  if (A === null && B === null) {
    throw new Error('both points are null!')
  } else if (A === null) {
    assert.exists(B)
    return B as CurveElement
  } else if (B === null) {
    return A
  } else {
    const C = A.add(B)
    C.assertValidity()
    return C as CurveElement
  }
}

/**
 * Multiplies a point by a scalar (scalar multiplication).
 *
 * Computes k * A where A is a point and k is a scalar.
 * This is the fundamental operation for deriving public keys from secrets.
 *
 * @param A - The base point
 * @param k - The scalar multiplier
 * @returns The resulting point k * A
 */
export function ScalarMulti (
  A : CurveElement,
  k : bigint
) {
  const pt = A.multiply(k)
  pt.assertValidity()
  return pt
}

/**
 * Multiplies the generator point G by a scalar.
 *
 * Computes k * G where G is the secp256k1 base point.
 * This is the standard operation for converting a secret key to a public key.
 *
 * @param k - The scalar multiplier (typically a secret key)
 * @returns The resulting point k * G (the corresponding public key)
 */
export function ScalarBaseMulti (k : bigint) {
  const base = secp256k1.Point.BASE
  const pt   = base.multiply(k)
  pt.assertValidity()
  return pt
}

/**
 * Serializes a curve element to compressed point format.
 *
 * Produces a 33-byte representation: 1 byte prefix (02 or 03 based on
 * y-coordinate parity) followed by 32 bytes of x-coordinate.
 *
 * @param A - The curve element to serialize
 * @returns A 33-byte Buff containing the compressed point
 */
export function SerializeElement (A : CurveElement) {
  return Buff.bytes(A.toBytes(true))
}

/**
 * Deserializes bytes to a curve element.
 *
 * Accepts either 33-byte compressed format or 65-byte uncompressed format.
 *
 * @param bytes - The serialized point bytes
 * @returns The deserialized curve element
 * @throws Error if the bytes do not represent a valid curve point
 */
export function DeserializeElement (bytes : Bytes) {
  const hex = Buff.bytes(bytes).hex
  return POINT.fromHex(hex)
}

/**
 * Serializes a scalar value to 32 bytes (big-endian).
 *
 * Ensures consistent scalar representation with zero-padding.
 *
 * @param scalar - The scalar value as bytes, number, or bigint
 * @returns A 32-byte Buff containing the scalar
 */
export function SerializeScalar (scalar : Bytes | number | bigint) {
  return new Buff(scalar, 32)
}
