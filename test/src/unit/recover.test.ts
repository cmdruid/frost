import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  gen_recovery_shares,
  recover_share,
  combine_set,
  get_share,
  verify_share
} from '@cmdcode/frost/lib'

import type { SecretShare } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('Recovery: Basic share recovery with threshold members', t => {
    // Create a 2-of-3 threshold group
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    // Store original share 3 for comparison
    const original_share_3 = group.shares.find(s => s.idx === 3)!

    // Members 1 and 2 will help recover share 3
    const members = [1, 2]
    const target = 3

    // Each member generates recovery shares
    const recovery_pkg_1 = gen_recovery_shares(members, group.shares[0], target, threshold)
    const recovery_pkg_2 = gen_recovery_shares(members, group.shares[1], target, threshold)

    t.equal(recovery_pkg_1.idx, 1, 'Recovery package 1 has correct source index')
    t.equal(recovery_pkg_2.idx, 2, 'Recovery package 2 has correct source index')

    // Collect recovery shares for each member
    const member_1_contributions = [
      get_share(recovery_pkg_1.shares, 1),
      get_share(recovery_pkg_2.shares, 1)
    ]
    const member_2_contributions = [
      get_share(recovery_pkg_1.shares, 2),
      get_share(recovery_pkg_2.shares, 2)
    ]

    // Each member aggregates their recovery contributions
    const agg_share_1 = combine_set(member_1_contributions)
    const agg_share_2 = combine_set(member_2_contributions)

    // Recover the share from aggregated contributions
    const recovered_share = recover_share([agg_share_1, agg_share_2], target)

    t.equal(recovered_share.idx, target, 'Recovered share has correct index')
    t.equal(recovered_share.seckey, original_share_3.seckey, 'Recovered share matches original')
    t.end()
  })

  tape.test('Recovery: Recovered share can participate in signing', t => {
    // Create a 2-of-3 group
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    // Recover share 3 using shares 1 and 2
    const members = [1, 2]
    const target = 3

    const recovery_pkg_1 = gen_recovery_shares(members, group.shares[0], target, threshold)
    const recovery_pkg_2 = gen_recovery_shares(members, group.shares[1], target, threshold)

    const member_1_contributions = [
      get_share(recovery_pkg_1.shares, 1),
      get_share(recovery_pkg_2.shares, 1)
    ]
    const member_2_contributions = [
      get_share(recovery_pkg_1.shares, 2),
      get_share(recovery_pkg_2.shares, 2)
    ]

    const agg_share_1 = combine_set(member_1_contributions)
    const agg_share_2 = combine_set(member_2_contributions)

    const recovered_share = recover_share([agg_share_1, agg_share_2], target)

    // Verify the recovered share using VSS
    const is_valid = verify_share(group.vss_commits, recovered_share, threshold)
    t.true(is_valid, 'Recovered share passes VSS verification')
    t.end()
  })

  tape.test('Recovery: Works with 3-of-5 threshold', t => {
    const threshold = 3
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    const original_share_5 = group.shares.find(s => s.idx === 5)!

    // Members 1, 2, and 3 recover share 5
    const members = [1, 2, 3]
    const target = 5

    const recovery_pkgs = members.map(idx => {
      const share = group.shares.find(s => s.idx === idx)!
      return gen_recovery_shares(members, share, target, threshold)
    })

    // Collect and aggregate contributions for each member
    const aggregated_shares: SecretShare[] = members.map(idx => {
      const contributions = recovery_pkgs.map(pkg => get_share(pkg.shares, idx))
      return combine_set(contributions)
    })

    const recovered_share = recover_share(aggregated_shares, target)

    t.equal(recovered_share.seckey, original_share_5.seckey, '3-of-5 recovery matches original')
    t.end()
  })

  tape.test('Recovery: VSS commitments are generated', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const members = [1, 2]
    const target = 3

    const recovery_pkg = gen_recovery_shares(members, group.shares[0], target, threshold)

    t.ok(recovery_pkg.vss_commits.length > 0, 'Recovery package contains VSS commits')
    t.ok(recovery_pkg.vss_commits.every(c => c.length === 66), 'VSS commits are valid pubkeys')
    t.end()
  })

  tape.test('Recovery: Error on insufficient members', t => {
    const threshold = 3
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    // Only 2 members, but threshold is 3
    const members = [1, 2]
    const target = 5

    try {
      gen_recovery_shares(members, group.shares[0], target, threshold)
      t.fail('Should throw error for insufficient members')
    } catch (e) {
      t.pass('Throws error when members < threshold')
    }
    t.end()
  })
}
