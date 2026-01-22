/**
 * @fileoverview Point State Management for BIP340/Taproot Compatibility
 *
 * Handles the complex parity tracking required when applying key tweaks
 * (such as Taproot tweaks) to FROST group keys. This ensures the final
 * signature is valid under BIP340's x-only public key scheme.
 */

import { Buff, Bytes }  from '@vbyte/buff'
import { _0n, _1n, _N } from '@/const.js'
import { mod_n }        from './util.js'
import * as G           from './group.js'

import {
  hasEvenY,
  type CurveElement,
  type PointState
} from '@/types/index.js'

/**
 * Computes the accumulative parity state for a given point with key tweaks.
 *
 * In BIP340 (Schnorr signatures for Bitcoin), public keys are represented as
 * x-only coordinates, implicitly assuming an even y-coordinate. When the
 * actual y-coordinate is odd, the secret key must be negated to match.
 *
 * When applying Taproot-style key tweaks (P' = P + t*G), the parity may flip
 * at each step. This function tracks the cumulative parity state so that
 * signing operations can correctly adjust secret shares.
 *
 * The returned state contains:
 * - `parity`: The current parity factor (+1 or -1 mod N) for the final point
 * - `point`: The final tweaked point
 * - `state`: The accumulated parity factor from all tweak applications
 * - `tweak`: The accumulated tweak value (adjusted for negations)
 *
 * @param element - The initial curve point (typically the group public key)
 * @param tweaks - Optional array of tweak values to apply sequentially
 * @returns The computed point state with parity tracking
 *
 * @example
 * // For Taproot key spending:
 * const state = get_point_state(groupPubkey, [taprootTweak])
 * // state.state is used to adjust secret shares when signing
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
    parity = hasEvenY(point) ? pos : neg
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

  parity = hasEvenY(point) ? pos : neg

  return { parity, point, state, tweak }
}
