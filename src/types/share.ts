export interface SecretShare {
  idx    : number,
  seckey : string
}

export interface PublicShare {
  idx    : number,
  pubkey : string
}

export interface SharePackage {
  sec_shares   : SecretShare[],
  vss_commits  : string[],
  group_pubkey : string
}


export interface PartialSignature {
  idx    : number,
  pubkey : string,
  psig   : string
}
