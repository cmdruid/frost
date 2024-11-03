import { combine_set, get_share } from '@cmdcode/frost/lib'  

import type { SecretShare } from '@cmdcode/frost'

export function collect_shares (
  groups : SecretShare[][],
  index  : number
) : SecretShare[] {
  const shares : SecretShare[] = []
  for (const group of groups) {
    const share = get_share(group, index)
    shares.push(share)
  }
  return shares
}

export function aggregate_shares (
  groups : SecretShare[][],
  index  : number
) : SecretShare {
  const shares = collect_shares(groups, index)
  return combine_set(shares)
}
