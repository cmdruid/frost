import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  gen_refresh_shares,
  refresh_share,
  combine_set,
  get_share,
  verify_share,
  derive_shares_secret,
  create_commit_pkg,
  sign_msg,
  combine_partial_sigs,
  verify_final_sig,
  get_group_signing_ctx
} from '@cmdcode/frost/lib'

import type { SecretShare, PublicNonce } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('Refresh: Basic share refresh (single dealer)', t => {
    // Create a 2-of-3 threshold group
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const original_secret = derive_shares_secret(group.shares)

    // A single "dealer" generates refresh shares for all participants
    // This simulates a trusted refresh dealer (simpler case)
    const refresh_pkg = gen_refresh_shares(0, threshold, share_max)

    // Each participant applies the refresh share
    const refreshed_shares: SecretShare[] = group.shares.map(share => {
      const contribution = get_share(refresh_pkg.shares, share.idx)
      return refresh_share([contribution], share)
    })

    // Secret should be unchanged (refresh polynomial has 0 constant term)
    const new_secret = derive_shares_secret(refreshed_shares)
    t.equal(new_secret, original_secret, 'Secret remains unchanged after refresh')

    // But individual shares should be different
    const any_changed = refreshed_shares.some((ns, i) =>
      ns.seckey !== group.shares[i].seckey
    )
    t.true(any_changed, 'At least one share value changed')
    t.end()
  })

  tape.test('Refresh: Refreshed shares produce valid signatures', t => {
    // Create group and refresh
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    // Generate refresh shares
    const refresh_pkg = gen_refresh_shares(0, threshold, share_max)

    // Apply refresh
    const refreshed_shares: SecretShare[] = group.shares.map(share => {
      const contribution = get_share(refresh_pkg.shares, share.idx)
      return refresh_share([contribution], share)
    })

    // Sign with refreshed shares (members 1 and 2)
    const message = Buff.str('test message').hex
    const signers = [refreshed_shares[0], refreshed_shares[1]]

    // Create commitments
    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    // Create signing context
    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    // Sign
    const psigs = signers.map((share, i) => {
      const snonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    // Combine and verify
    const signature = combine_partial_sigs(ctx, psigs)
    const key_ctx = { group_pk: group.group_pk, group_pt: ctx.group_pt }
    const is_valid = verify_final_sig(key_ctx, message, signature)

    t.true(is_valid, 'Signature with refreshed shares is valid')
    t.end()
  })

  tape.test('Refresh: Group public key unchanged after refresh', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const original_secret = derive_shares_secret(group.shares)

    // Refresh all shares
    const refresh_pkg = gen_refresh_shares(0, threshold, share_max)

    const refreshed_shares: SecretShare[] = group.shares.map(share => {
      const contribution = get_share(refresh_pkg.shares, share.idx)
      return refresh_share([contribution], share)
    })

    // The best way to verify the group key is to check the secret is unchanged
    const new_secret = derive_shares_secret(refreshed_shares)
    t.equal(new_secret, original_secret, 'Group secret (and thus pubkey) unchanged')
    t.end()
  })

  tape.test('Refresh: Multiple refresh rounds', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const original_secret = derive_shares_secret(group.shares)
    let current_shares = [...group.shares]

    // Perform 3 rounds of refresh
    for (let round = 0; round < 3; round++) {
      const refresh_pkg = gen_refresh_shares(round, threshold, share_max)

      current_shares = current_shares.map(share => {
        const contribution = get_share(refresh_pkg.shares, share.idx)
        return refresh_share([contribution], share)
      })
    }

    const final_secret = derive_shares_secret(current_shares)
    t.equal(final_secret, original_secret, 'Secret unchanged after multiple refreshes')
    t.end()
  })

  tape.test('Refresh: VSS commits are generated for verification', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const refresh_pkg = gen_refresh_shares(1, threshold, share_max)

    // VSS commits should have threshold - 1 entries (since constant term is 0)
    t.equal(refresh_pkg.vss_commits.length, threshold - 1, 'Correct number of VSS commits')
    t.ok(refresh_pkg.vss_commits.every(c => c.length === 66), 'VSS commits are valid pubkeys')
    t.end()
  })

  tape.test('Refresh: Works with larger threshold (3-of-5)', t => {
    const threshold = 3
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    const original_secret = derive_shares_secret(group.shares)

    const refresh_pkg = gen_refresh_shares(0, threshold, share_max)

    const refreshed_shares: SecretShare[] = group.shares.map(share => {
      const contribution = get_share(refresh_pkg.shares, share.idx)
      return refresh_share([contribution], share)
    })

    const new_secret = derive_shares_secret(refreshed_shares)
    t.equal(new_secret, original_secret, '3-of-5 refresh preserves secret')
    t.end()
  })

  tape.test('Refresh: Distributed refresh with multiple contributors', t => {
    // In a proper distributed refresh, multiple participants contribute
    // and ALL participants apply ALL contributions
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const original_secret = derive_shares_secret(group.shares)

    // Two participants contribute refresh shares
    const refresh_pkg_1 = gen_refresh_shares(1, threshold, share_max)
    const refresh_pkg_2 = gen_refresh_shares(2, threshold, share_max)

    // ALL participants apply ALL refresh contributions
    const refreshed_shares: SecretShare[] = group.shares.map(share => {
      const contrib_1 = get_share(refresh_pkg_1.shares, share.idx)
      const contrib_2 = get_share(refresh_pkg_2.shares, share.idx)
      return refresh_share([contrib_1, contrib_2], share)
    })

    const new_secret = derive_shares_secret(refreshed_shares)
    t.equal(new_secret, original_secret, 'Distributed refresh preserves secret')
    t.end()
  })
}
