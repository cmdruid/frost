import { Buff, Bytes } from '@cmdcode/buff'
import { _N }          from '@/const.js'
import { mod_n }       from './util.js'
import * as G          from './group.js'

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
  // Convert our tweaks to bigints.
  const ints = tweaks.map(e => mod_n(Buff.bytes(e).big))
  // Define the positive scalar.
  const pos  = BigInt(1)
  // Define the negative (inverse) scalar.
  const neg  = _N - pos

  let point : CurveElement = element,
      parity = pos, // Handles negation for current round.
      state  = pos, // Tracks negation state across rounds.
      tweak  = 0n   // Stores the accumulated (negated) tweak.

  for (const t of ints) {
    // If point is odd, g should be negative.
    parity = (!point.hasEvenY()) ? neg : pos
    // Invert point based on g, then add tweak.
    point  = G.ElementAdd(G.ScalarMulti(point, parity), G.ScalarBaseMulti(t))
    // Assert that point is not null.
    point.assertValidity()
    // Store our progress for the next round.
    state = mod_n(parity * state)
    tweak = mod_n(t + parity * tweak)
  }
  
  // Set parity to the current point state.
  parity = (!point.hasEvenY()) ? neg : pos

  return { point, parity, state, tweak }
}
