import { PointState } from './ecc.js'

import { BindFactor, PublicNonce } from './nonce.js'

export type GroupSessionCtx = GroupKeyContext & GroupCommitContext

export interface GroupKeyContext {
  group_state   : PointState
  group_pubkey  : string
  int_state    ?: PointState
  int_pubkey   ?: string
  key_tweak    ?: string
}

export interface GroupCommitContext {
  bind_prefix  : string,
  bind_factors : BindFactor[],
  challenge    : bigint,
  group_pnonce : string,
  identifiers  : bigint[],
  message      : string,
  pub_nonces   : PublicNonce[],
}
