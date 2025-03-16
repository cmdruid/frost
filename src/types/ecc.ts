import { ProjPointType } from '@noble/curves/abstract/weierstrass'

export type CurveElement = ProjPointType<bigint>

export interface PointState {
  parity : bigint
  point  : CurveElement
  state  : bigint
  tweak  : bigint
}
