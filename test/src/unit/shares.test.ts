import { Test }       from 'tape'
import { SpecVector } from '../types.js'
import { get_record } from '@cmdcode/frost/util'

import {
  create_dealer_set,
  derive_shares_secret,
  verify_share
} from '@cmdcode/frost/lib'

export default function (tape : Test, vector : SpecVector) {
  const { commits, secrets, share_min, share_max } = vector.group
  tape.test('Testing share commitments', t => {
    const group = create_dealer_set(share_min, share_max, secrets)

    for (let i = 0; i < group.vss_commits.length; i++) {
      t.equal(group.vss_commits[i], commits[i], `[${i}] commit key matches vector`)
    }

    t.equal(group.group_pk, commits[0], 'root commit should equal group pubkey')

    for (const mbr of vector.members) {
      const share    = get_record(group.shares, mbr.idx)
      const is_valid = verify_share(group.vss_commits, share, share_min)
      t.equal(share.seckey, mbr.seckey, `[${mbr.idx}] share key matches vector`)
      t.true(is_valid, `[${mbr.idx}] share commit is valid using vss`)
    }

    const secret = derive_shares_secret(group.shares)
    t.equal(secret, secrets[0], 'combined shares matches root secret')

    t.end()
  })
}
