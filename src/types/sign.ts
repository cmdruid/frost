import { CommitPackage } from './commit.js'
import { SharePackage }  from './share.js'
import { Package }       from './util.js'

export type MemberPackage    = Package<Membership>
export type SignaturePackage = Package<ShareSignature>

export interface Membership {
  commit : CommitPackage
  share  : SharePackage
}

export interface ShareSignature {
  pubkey : string,
  psig   : string
}
