export interface SecretPackage {
  idx       : number
  binder_sn : string
  hidden_sn : string
  share_sk  : string
}

export interface CommitPackage {
  idx       : number
  binder_pn : string
  hidden_pn : string
  share_pk  : string
}

export interface GroupPackage {
  commits   : CommitPackage[]
  group_pk  : string
  threshold : number
}

export interface DealerPackage extends GroupPackage {
  secrets : SecretPackage[]
}

