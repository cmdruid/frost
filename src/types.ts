import { CurveElement } from './ecc/types.js'

export type FrostContext = KeyContext & CommitContext

export interface SecretShare {
  idx    : number,
  seckey : string
}

export interface PublicShare {
  idx    : number,
  pubkey : string
}

export interface SecretNonce {
  idx      : number
  snonce_h : string
  snonce_b : string
}

export interface PublicNonce {
  idx      : number,
  pnonce_h : string,
  pnonce_b : string
}

export interface NonceBinder {
  idx : number,
  key : string
}

export interface SignatureShare {
  idx : number,
  sig : string
}

export interface SharePackage {
  sec_shares   : SecretShare[],
  vss_commits  : string[],
  group_pubkey : string
}

export interface NonceData {
  sec_nonces : SecretNonce,
  pub_nonces : PublicNonce
}

export interface PointState {
  point  : CurveElement
  parity : bigint
  state  : bigint
  tweak  : bigint
}

export interface KeyContext {
  group_state   : PointState
  group_pubkey  : string
  int_state    ?: PointState
  int_pubkey   ?: string
  key_tweak    ?: string
}

export interface CommitContext extends KeyContext {
  bind_prefix  : string,
  bind_factors : NonceBinder[],
  challenge    : bigint,
  group_pnonce : string,
  identifiers  : bigint[],
  message      : string,
  pub_nonces   : PublicNonce[],
}
