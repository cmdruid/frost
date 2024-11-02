import { CommitPackage } from './commit.js'
import { SecretShare }   from './share.js'

export interface Membership {
  idx    : number
  commit : CommitPackage
  share  : SecretShare
}

export interface ShareSignature {
  idx    : number
  pubkey : string,
  psig   : string
}
