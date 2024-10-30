import { Package } from './util.js'

export type NonceCommit        = SecretNonce & PublicNonce
export type BinderPackage      = Package<BindFactor>
export type CommitPackage      = Package<NonceCommit>
export type PublicNoncePackage = Package<PublicNonce>
export type SecretNoncePackage = Package<SecretNonce>

export interface SecretNonce {
  binder_sn : string
  hidden_sn : string
}

export interface PublicNonce {
  binder_pn : string,
  hidden_pn : string
}

export interface BindFactor {
  bind_hash : string
}
