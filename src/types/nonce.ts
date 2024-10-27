export interface NoncePackage {
  idx      : number
  pubnonce : PublicNonce
  secnonce : SecretNonce
}

export interface SecretNonce {
  idx       : number
  binder_sn : string
  hidden_sn : string
}

export interface PublicNonce {
  idx       : number,
  binder_pn : string,
  hidden_pn : string
}

export interface BindFactor {
  idx : number,
  key : string
}
