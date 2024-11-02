export type SharePackage = ShareGroup & { idx : number }

export interface SecretShare {
  idx    : number
  seckey : string
}

export interface ShareSet {
  idx    : number
  shares : SecretShare[]
}

export interface ShareGroup {
  commits : string[]
  shares  : SecretShare[]
}

export interface KeyGroup extends ShareGroup {
  commits : string[]
  pubkey  : string
  shares  : SecretShare[]
}
