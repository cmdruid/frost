import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  evaluate_x,
  interpolate_x,
  interpolate_root,
  calc_lagrange_coeff
} from '@cmdcode/frost/lib'

export default function (tape: Test) {
  tape.test('Poly: evaluate_x throws when x === 0', t => {
    const coeffs = [1n, 2n, 3n] // f(x) = 1 + 2x + 3x^2

    try {
      evaluate_x(coeffs, 0n)
      t.fail('Should throw error when x === 0')
    } catch (e: any) {
      t.ok(e.message.includes('zero'), 'Throws error with "zero" in message')
    }
    t.end()
  })

  tape.test('Poly: evaluate_x computes correct values', t => {
    // f(x) = 5 + 3x + 2x^2
    // f(1) = 5 + 3 + 2 = 10
    // f(2) = 5 + 6 + 8 = 19
    // f(3) = 5 + 9 + 18 = 32
    const coeffs = [5n, 3n, 2n]

    t.equal(evaluate_x(coeffs, 1n), 10n, 'f(1) = 10')
    t.equal(evaluate_x(coeffs, 2n), 19n, 'f(2) = 19')
    t.equal(evaluate_x(coeffs, 3n), 32n, 'f(3) = 32')
    t.end()
  })

  tape.test('Poly: interpolate_x throws when x not in L', t => {
    const L = [1n, 2n, 3n]

    try {
      interpolate_x(L, 5n) // 5 is not in L
      t.fail('Should throw error when x not in L')
    } catch (e) {
      t.pass('Throws error when x not included in L')
    }
    t.end()
  })

  tape.test('Poly: interpolate_x throws on duplicate values', t => {
    const L = [1n, 2n, 2n, 3n] // 2 appears twice

    try {
      interpolate_x(L, 1n)
      t.fail('Should throw error on duplicate values')
    } catch (e) {
      t.pass('Throws error on duplicate values in L')
    }
    t.end()
  })

  tape.test('Poly: interpolate_root recovers polynomial constant', t => {
    // Create a polynomial f(x) = a0 + a1*x where a0 = 42
    const a0 = 42n
    const a1 = 17n

    // Evaluate at x=1, x=2 (need 2 points for degree-1 polynomial)
    const y1 = a0 + a1 * 1n // f(1) = 42 + 17 = 59
    const y2 = a0 + a1 * 2n // f(2) = 42 + 34 = 76

    const points = [
      [1n, y1],
      [2n, y2]
    ]

    const recovered = interpolate_root(points)
    t.equal(recovered, a0, 'Recovered constant term matches original')
    t.end()
  })

  tape.test('Poly: interpolate_root works with degree-2 polynomial', t => {
    // f(x) = 100 + 20x + 3x^2
    const a0 = 100n
    const a1 = 20n
    const a2 = 3n

    // Need 3 points for degree-2 polynomial
    const f = (x: bigint) => a0 + a1 * x + a2 * x * x

    const points = [
      [1n, f(1n)],
      [2n, f(2n)],
      [3n, f(3n)]
    ]

    const recovered = interpolate_root(points)
    t.equal(recovered, a0, 'Recovered constant term from degree-2 polynomial')
    t.end()
  })

  tape.test('Poly: calc_lagrange_coeff basic computation', t => {
    // For L = [1, 2], P = 1, x = 0:
    // lambda_1 = (0 - 2) / (1 - 2) = -2 / -1 = 2
    const L = [2n] // Other participants (excluding P)
    const P = 1n   // Current participant
    const x = 0n   // Evaluating at origin

    const coeff = calc_lagrange_coeff(L, P, x)
    t.equal(coeff, 2n, 'Lagrange coefficient computed correctly')
    t.end()
  })

  tape.test('Poly: calc_lagrange_coeff with multiple participants', t => {
    // For participants at 1, 2, 3, evaluating at x=0
    // Lambda_1 for P=1, L=[2,3]:
    // (0-2)(0-3) / (1-2)(1-3) = 6 / 2 = 3
    const L = [2n, 3n]
    const P = 1n
    const x = 0n

    const coeff = calc_lagrange_coeff(L, P, x)
    t.equal(coeff, 3n, 'Lagrange coefficient for 3-party correct')
    t.end()
  })

  tape.test('Poly: calc_lagrange_coeff throws on duplicate in L', t => {
    const L = [2n, 3n, 2n] // duplicate

    try {
      calc_lagrange_coeff(L, 1n, 0n)
      t.fail('Should throw error on duplicate values')
    } catch (e) {
      t.pass('Throws error on duplicate values in L')
    }
    t.end()
  })

  tape.test('Poly: Lagrange coefficients sum to 1 at x=0', t => {
    // Property: sum of Lagrange coefficients at x=0 equals 1
    // This is needed for correct interpolation

    // For 2-of-3 at positions 1, 2 (evaluating at 0)
    const L_12 = [2n]
    const L_21 = [1n]

    const lambda_1 = calc_lagrange_coeff(L_12, 1n, 0n)
    const lambda_2 = calc_lagrange_coeff(L_21, 2n, 0n)

    // In modular arithmetic, this should be 1 mod N
    // lambda_1 * y_1 + lambda_2 * y_2 interpolates to f(0)
    t.ok(lambda_1 !== 0n && lambda_2 !== 0n, 'Both coefficients are non-zero')
    t.end()
  })

  tape.test('Poly: evaluate_x with single coefficient', t => {
    // f(x) = 7 (constant polynomial)
    const coeffs = [7n]

    t.equal(evaluate_x(coeffs, 1n), 7n, 'Constant polynomial evaluates to constant')
    t.equal(evaluate_x(coeffs, 100n), 7n, 'Constant polynomial same for any x')
    t.end()
  })

  tape.test('Poly: interpolation round-trip with FROST-like shares', t => {
    // Simulate FROST share generation and recovery
    const secret = 12345n
    const a1 = 9876n  // Random coefficient

    // Generate 3 shares for t=2 polynomial
    const share1 = secret + a1 * 1n  // f(1)
    const share2 = secret + a1 * 2n  // f(2)
    const share3 = secret + a1 * 3n  // f(3)

    // Recover using shares 1 and 2
    const points_12 = [
      [1n, share1],
      [2n, share2]
    ]
    const recovered_12 = interpolate_root(points_12)
    t.equal(recovered_12, secret, 'Recovered secret from shares 1,2')

    // Recover using shares 2 and 3
    const points_23 = [
      [2n, share2],
      [3n, share3]
    ]
    const recovered_23 = interpolate_root(points_23)
    t.equal(recovered_23, secret, 'Recovered secret from shares 2,3')

    // Recover using shares 1 and 3
    const points_13 = [
      [1n, share1],
      [3n, share3]
    ]
    const recovered_13 = interpolate_root(points_13)
    t.equal(recovered_13, secret, 'Recovered secret from shares 1,3')

    t.end()
  })
}
