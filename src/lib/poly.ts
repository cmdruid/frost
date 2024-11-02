import { _0n, _1n, FIELD }  from '@/const.js'
import { mod_n }            from '@/ecc/util.js'
import { assert }           from '@/util/index.js'

/**
 * Evaluates a polynomial at a given value `x` using the provided coefficients `L`.
 * The polynomial is of the form:
 * 
 * L[0] + L[1] * x + L[2] * x^2 + ... + L[n] * x^n
 * 
 * The coefficients are processed in reverse order, using Horner's method
 * to optimize the computation.
 * 
 * @param L : Array of coefficients in ascending order of powers.
 * @param x : The value at which to evaluate the polynomial.
 * @returns : The result of the polynomial evaluation.
 * @throws  : Will throw an error if `x` is zero.
 */
export function evaluate_x (
  L: bigint[],
  x: bigint
) {
  if (x === _0n) {
    throw new Error('x is zero')
  }
  
  // Initialize the result to zero.
  let value = _0n
  
  // Iterate over the coefficients in reverse order:
  for (const coeff of [ ...L ].reverse()) {
    // Multiply the current value by x (shift to the next power of x).
    value *= x
    // Add the current coefficient to the value.
    value += coeff
    // Ensure the result is reduced to the field value.
    value = mod_n(value)
  }
  
  // Return the final evaluated value of the polynomial.
  return value
}

/**
 * Interpolates a polynomial at the root based on the given points using Lagrange interpolation.
 * Each point in the input is treated as (x, y) where `x` is the x-coordinate and `y` is the
 * corresponding y-coordinate.
 * 
 * The function returns the evaluated polynomial at the root (i.e., when x = 0).
 * 
 * @param points An array of points, where each point is a tuple [x, y] of bigints.
 * @returns      The value of the interpolated polynomial at the root (x = 0).
 */
export function interpolate_root (
  points: bigint[][]
) {
  // Extract the x-coordinates from the points.
  const coeffs = points.map(e => e[0])
  
  // Initialize the polynomial result to zero.
  let p = _0n
  
  // Loop through each point [x, y] in the provided points:
  for (const [ x, y ] of points) {
    // Interpolate and get the delta value for the current x-coordinate.
    const delta = interpolate_x(coeffs, x)
    // Multiply delta by the y-coordinate of the current point and add to the result.
    p += delta * y
    // Reduce the result to the field value (mod n).
    p = mod_n(p)
  }
  
  // Return the final interpolated value at the root (x = 0).
  return p
}

/**
 * Computes the Lagrange interpolation factor for a given x-coordinate `x` in the polynomial
 * defined by the set of x-coordinates `L`. This is a helper function used for Lagrange interpolation.
 * 
 * It returns the value of the Lagrange basis polynomial at `x`, which is the quotient of
 * the product of differences between `x_j` values in `L` and `x`, divided by the difference
 * in corresponding denominators.
 * 
 * @param L Array of x-coordinates (bigints) representing the known points.
 * @param x The x-coordinate for which to compute the interpolation factor.
 * @returns The computed Lagrange interpolation factor for the given x.
 * @throws  Will throw an error if `x` is not included in `L` or if the set `L` contains duplicates.
 */
export function interpolate_x (
  L: bigint[],
  x: bigint
): bigint {
  // Ensure x is included in L and that L has unique elements.
  assert.is_included(L, x)
  assert.is_unique_set(L)

  // Initialize numerator and denominator for the interpolation factor.
  let numerator   = _1n,
      denominator = _1n

  // Loop through each x_j in L to calculate the Lagrange basis polynomial:
  for (const x_j of L) {
    // Skip the current x to avoid division by zero.
    if (x_j === x) continue
    // Update the numerator: multiply by x_j.
    numerator = mod_n(FIELD.mul(numerator, x_j))
    // Update the denominator: multiply by (x_j - x).
    denominator = mod_n(FIELD.mul(denominator, x_j - x))
  }

  // Return the final interpolation factor, computed as numerator/denominator, reduced mod n.
  return mod_n(FIELD.div(numerator, denominator))
}

/**
 * Calculate the Lagrange coefficient for a participant,
 * relative to other participants.
 * 
 * @param L A list of other participant indexes.
 * @param P Index of the primary participant.
 * @param x The point to evaluate.
 * @returns A bigint representing the lagrange coefficient.
 */
export function calc_lagrange_coeff (
  L : bigint[],
  P : bigint,
  x : bigint
): bigint {
  // Ensure that L has unique elements.
  assert.is_unique_set(L)

  // Initialize numerator and denominator.
  let numerator   = _1n,
      denominator = _1n

  // Loop through each index in L:
  for (const x_j of L) {
    // Skip the participant index.
    if (x_j === P) continue
    // Update the numerator:
    numerator   = mod_n(FIELD.mul(numerator,   x - x_j))
    // Update the denominator:
    denominator = mod_n(FIELD.mul(denominator, P - x_j))
  }

  // Return the lagrange coefficient.
  return mod_n(FIELD.div(numerator, denominator))
}
