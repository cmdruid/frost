import { SecretShare } from './share.js'

export type MemberSecretPackage = MemberSecretData & GroupCommitData
export type MemberPublicPackage = MemberPublicData & GroupCommitData

export interface MemberPublicData {
  idx      : number
  root_pn  : string
  share_pk : string
}

export interface MemberSecretData extends MemberPublicData {
  root_sn  : string
  share_sk : string
}

export interface GroupCommitData {
  group_pk  : string
  pubcoeffs : string[]
  pubnonces : string[]
  threshold : number
}

export interface TrustedDealerPackage {
  sec_shares   : SecretShare[],
  vss_commits  : string[],
  group_pubkey : string
}
