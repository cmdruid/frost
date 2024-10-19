import { Test }                  from 'tape'
import { SpecVector }            from './types.js'
import { get_record }            from '@/util.js'

import {
  create_share_package,
  combine_secret_shares,
  verify_share_commit
} from '@/shares.js'

export default function (tape : Test, vector : SpecVector) {
  const { commits, secrets, share_min, share_max } = vector.group
  tape.test('Testing share commitments', t => {
    const pkg = create_share_package(secrets, share_min, share_max)

    for (let i = 0; i < commits.length; i++) {
      t.equal(pkg.vss_commits[i], commits[i], `[${i}] commit key matches vector`)
    }

    t.equal(pkg.group_pubkey, commits[0], 'root commit should equal group pubkey')

    for (const mbr of vector.members) {
      const share    = get_record(pkg.sec_shares, mbr.idx)
      const is_valid = verify_share_commit(pkg.vss_commits, share, share_min)
      t.equal(share.seckey, mbr.seckey, `[${mbr.idx}] share key matches vector`)
      t.true(is_valid, `[${mbr.idx}] share commit is valid using vss`)
    }

    const secret = combine_secret_shares(pkg.sec_shares)
    t.equal(secret, secrets[0], 'combined shares matches root secret')

    t.end()
  })
}
