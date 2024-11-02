import { combine_shares, get_share } from '@cmdcode/frost/lib'  

import type { SecretShare } from '@cmdcode/frost'

// export function combine_dkg_shares (
//   share_sets : SecretShare[][]
// ) : SecretShare[] {
//   // TODO: We should assert that all sets have matching indexes.
//   const aggregate_shares : SecretShare[] = []
//   const members = share_sets[0].map(e => e.idx).sort()
//   for (const idx of members) {
//     const mbr_shares : SecretShare[] = []
//     for (const shares of share_sets) {
//       const share = get_share(shares, idx)
//       mbr_shares.push(share)
//     }
//     const aggregate_share = combine_shares(mbr_shares)
//     aggregate_shares.push(aggregate_share)
//   }
//   return aggregate_shares
// }

export function aggregate_shares (
  groups : SecretShare[][],
  index  : number
) : SecretShare {
  const shares : SecretShare[] = []
  for (const group of groups) {
    const share = get_share(group, index)
    shares.push(share)
  }
  return combine_shares(shares)
}
