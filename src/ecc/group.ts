// As specified in draft-irtf-cfrg-frost-15, section 3.1.
// https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html

import { Buff, Bytes } from '@cmdcode/buff'
import { secp256k1 }   from '@noble/curves/secp256k1'
import { assert }      from '@/util/index.js'
import { mod_n }       from './util.js'

import type { CurveElement } from '@/types/index.js'

import CONST from '@/const.js'

const { POINT, _0n, _1n, _N } = CONST

export function Order () : bigint {
  return _N
}

export function Identity () : CurveElement {
  return new POINT(_0n, _1n, _0n)
}

export function RandomScalar () {
  const bigint = Buff.random(32).big
  return mod_n(bigint)
}

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

export function ElementAddMany (
  elem : Array<CurveElement | null>
) : CurveElement {
  const sum = elem.slice(1).reduce((p, c) => ElementAdd(p, c), elem[0])
  if (sum === null) {
    throw new Error('Summed point is null.')
  }
  sum.assertValidity()
  return sum
}

export function ScalarMulti (
  A : CurveElement,
  k : bigint
) {
  const pt = A.multiply(k)
  pt.assertValidity()
  return pt
}

export function ScalarBaseMulti (k : bigint) {
  const base = secp256k1.ProjectivePoint.BASE
  const pt   = base.multiply(k)
  pt.assertValidity()
  return pt
}

export function SerializeElement (A : CurveElement) {
  return Buff.bytes(A.toRawBytes(true))
}

export function DeserializeElement (bytes : Bytes) {
  const hex = Buff.bytes(bytes).hex
  return POINT.fromHex(hex)
}

export function SerializeScalar (scalar : Bytes) {
  return new Buff(scalar, 32)
}

export function DeserializeScalar (bytes : Bytes) {
  return Buff.bytes(bytes).big
}
