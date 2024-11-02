import { PointState } from './ecc.js'

import { BindFactor, PublicNonce } from './commit.js'

export type GroupSessionCtx = GroupKeyContext & GroupCommitContext

export interface GroupKeyContext {
  group_pt : PointState
  group_pk : string
  int_pt  ?: PointState
  int_pk  ?: string
  tweak   ?: string
}

export interface GroupCommitContext {
  bind_factors : BindFactor[],
  bind_prefix  : string,
  challenge    : bigint,
  group_pn     : string,
  indexes      : bigint[],
  message      : string,
  pnonces      : PublicNonce[]
}
