export type SecretSharePackage = SecretShareSet & { idx : number }

export interface SecretShare {
  idx    : number
  seckey : string
}

export interface PublicShare {
  idx    : number
  pubkey : string
}

export interface SecretShareSet {
  shares      : SecretShare[]
  vss_commits : string[]
}

export interface DealerShareSet extends SecretShareSet {
  group_pk : string
}
