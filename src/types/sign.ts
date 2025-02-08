import { CommitmentPackage } from './commit.js'
import { SecretShare }   from './share.js'

export interface ShareProfile {
  idx    : number
  commit : CommitmentPackage
  share  : SecretShare
}

export interface ShareSignature {
  idx    : number
  pubkey : string,
  psig   : string
}
