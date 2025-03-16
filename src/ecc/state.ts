import { Buff, Bytes }  from '@cmdcode/buff'
import { _0n, _1n, _N } from '@/const.js'
import { mod_n }        from './util.js'
import * as G           from './group.js'

import type {
  CurveElement,
  PointState
} from '@/types/index.js'

/**
 * Computes the accumulative parity state for a given point,
 * with optional key tweaks provided.
 */

export function get_point_state (
  element : CurveElement,
  tweaks  : Bytes[] = []
) : PointState {
  const ints = tweaks.map(e => Buff.bytes(e).big)
  const pos  = _1n
  const neg  = _N - pos

  // Define our working variables.
  let point : CurveElement = element,
      parity = pos, // Handles negation for current round.
      state  = pos, // Stores the accumulated (negated) tweak.
      tweak  = _0n  // Stores the accumulated (negated) tweak.

  // Iterate through the tweaks:
  for (const t of ints) {
    // Convert the tweak bigint into a point on the curve.
    const tG = G.ScalarBaseMulti(t)
    // Set the parity value based on the point's y-coordinate.
    parity = point.hasEvenY() ? pos : neg
    // Negate the point if the parity is odd.
    point = (parity === neg) ? point.negate() : point
    // Add the tweak point to the current point.
    point = G.ElementAdd(point, tG)
    // Assert that point is valid.
    point.assertValidity()
    // Update the parity state with the current value.
    state = mod_n(parity * state)
    // Update the tweak state with the current value.
    tweak = mod_n(t + (parity * tweak))
  }

  parity = point.hasEvenY() ? pos : neg

  return { parity, point, state, tweak }
}
