// import { CurveElement } from './ecc/types.js'

// export type FrostContext = KeyContext & CommitContext

// export interface SecretShare {
//   idx    : number,
//   seckey : string
// }

// export interface PublicShare {
//   idx    : number,
//   pubkey : string
// }

// export interface SecretNonce {
//   idx       : number
//   binder_sn : string
//   hidden_sn : string
// }

// export interface PublicNonce {
//   idx       : number,
//   binder_pn : string,
//   hidden_pn : string
// }

// export interface BindFactor {
//   idx : number,
//   key : string
// }

// export interface SignatureShare {
//   idx : number,
//   sig : string
// }

// export interface NonceData {
//   hidden_sn : string
//   hidden_pn : string
//   binder_sn : string
//   binder_pn : string
// }

// export interface NoncePackage extends NonceData {
//   idx : number
// }

// export interface PointState {
//   point  : CurveElement
//   parity : bigint
//   state  : bigint
//   tweak  : bigint
// }

// export interface KeyContext {
//   group_state   : PointState
//   group_pubkey  : string
//   int_state    ?: PointState
//   int_pubkey   ?: string
//   key_tweak    ?: string
// }

// export interface CommitContext extends KeyContext {
//   bind_prefix  : string,
//   bind_factors : BindFactor[],
//   challenge    : bigint,
//   group_pnonce : string,
//   identifiers  : bigint[],
//   message      : string,
//   pub_nonces   : PublicNonce[],
// }
