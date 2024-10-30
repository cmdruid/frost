import { Package } from './util.js'

export type SharePackage = Package<SecretShare>

export interface SecretShare {
  seckey : string
}

export interface ShareGroup {
  commits : string[],
  pubkey  : string
  shares  : SharePackage[],
}
