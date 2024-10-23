import { ProjPointType } from '@noble/curves/abstract/weierstrass'

export type CurveElement = ProjPointType<bigint>

export interface PointState {
  point  : CurveElement
  parity : bigint
  state  : bigint
  tweak  : bigint
}
