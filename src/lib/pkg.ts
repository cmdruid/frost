import { get_record }         from '@/util/helpers.js'
import { create_commit_pkg }  from './proto.js'
import { create_share_pkg }   from './shares.js'
import { get_pubkey }         from './util.js'

import { sign_msg, verify_partial_sig } from './sign.js'

import type {
  CommitPackage,
  DealerPackage,
  GroupPackage,
  GroupSessionCtx,
  PartialSignature,
  SecretPackage
} from '@/types/index.js'
import { get_session_ctx } from './context.js'

export function create_dealer_pkg (
  seeds     : string[],
  threshold : number,
  share_ct  : number
) : DealerPackage {
  const share_pkg = create_share_pkg(seeds, threshold, share_ct)
  const group_pk  = share_pkg.group_pubkey

  const commits : CommitPackage[] = []
  const secrets : SecretPackage[] = []

  for (const share of share_pkg.sec_shares) {
    const idx       = share.idx
    const share_sk  = share.seckey
    const share_pk  = get_pubkey(share_sk)
    const nonce_pkg = create_commit_pkg(share)
    const { binder_sn, hidden_sn } = nonce_pkg.secnonce
    const { binder_pn, hidden_pn } = nonce_pkg.pubnonce
    commits.push({ idx, binder_pn, hidden_pn, share_pk })
    secrets.push({ idx, binder_sn, hidden_sn, share_sk })
  }

  return { commits, group_pk, secrets, threshold }
}

// export function rotate_dealer_pkg (
//   group_pkg   : GroupPackage,
//   secret_pkgs : SecretPackage[]
// ) : DealerPackage {
//   // Generate new shares.

// }

export function get_package_ctx (
  pkg     : GroupPackage,
  message : string,
  tweaks? : string[]
) {
  const { commits, group_pk } = pkg
  return get_session_ctx(group_pk, commits, message, tweaks)
}

export function create_psig_pkg (
  ctx  : GroupSessionCtx,
  spkg : SecretPackage
) {
  const { idx, share_sk, binder_sn, hidden_sn } = spkg
  const secnonce = { idx, binder_sn, hidden_sn }
  const secshare = { idx, seckey: share_sk }
  return sign_msg(ctx, secshare, secnonce)
}

export function verify_psig_pkg (
  ctx  : GroupSessionCtx,
  psig : PartialSignature
) {
  const pnonce = get_record(ctx.pub_nonces, psig.idx)
  return verify_partial_sig(ctx, pnonce, psig.pubkey, psig.psig)
}
