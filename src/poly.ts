import { Buff, Bytes }      from '@cmdcode/buff'
import { mod_n }            from './ecc/util.js'
import { _0n, _1n, field }  from './ecc/const.js'

import * as assert from './assert.js'

/**
 * Create a list of coefficients, with optional seeds.
 */
export function create_coeffs (
  secrets   : Bytes[],
  threshold : number,
) {
  const coeffs : bigint[] = []
  for (let i = 0; i < threshold; i++) {
    const secret = secrets.at(i)
    const coeff  = (secret !== undefined)
      ? new Buff(secret)
      : Buff.random(32)
    coeffs.push(mod_n(coeff.big))
  }
  return coeffs
}

/**
 * Evaluate a polynomial at a given index (x).
 */
export function evaluate_x (
  L : bigint[],
  x : bigint
) {
  if (x === _0n) {
    throw new Error('x is zero')
  }
  // Start with a zero value.
  let value = _0n
  // For each coefficient (in reverse order):
  for (const coeff of [ ...L ].reverse()) {
    // Multiply by the index (x).
    value *= x
    // Add the coefficient.
    value += coeff
    // Convert to a field value.
    value = mod_n(value)
  }
  // Return the final value.
  return value
}

/**
 * Interpolate a list of points and return the root.
 */
export function interpolate_root (
  points : bigint[][]
) {
  // Get a list of x-coordinates.
  const coeffs = points.map(e => e[0])
  // Init our polynomial at zero.
  let p = _0n
  // For each data point in our array:
  for (const [ x, y ] of points) {
    // Evaluate the coefficients at x.
    const delta = interpolate_x(coeffs, x)
    // Multiply the sum by y
    p += delta * y
    p = mod_n(p)
  }
  // Return the final value.
  return p
}

/**
 * Evaluate a given x value from a list of coefficients,
 * using lagrange interpolation.
 */
export function interpolate_x (
  L : bigint[],
  x : bigint
) : bigint {
  // Assert x is included and coefficients are unique.
  assert.is_included(L, x)
  assert.is_unique_set(L)

  let numerator   = _1n,
      denominator = _1n

  for (const x_j of L) {
    // Skip x when iterating.
    if (x_j === x) continue
    // Update the numerator and denominator
    numerator   = mod_n(field.mul(numerator, x_j))
    denominator = mod_n(field.mul(denominator, x_j - x))
  }
  // Return the field quotient, mod n.
  return mod_n(field.div(numerator, denominator))
}
