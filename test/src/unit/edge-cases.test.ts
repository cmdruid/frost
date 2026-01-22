import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  create_commit_pkg,
  sign_msg,
  combine_partial_sigs,
  verify_final_sig,
  verify_share,
  combine_set,
  create_shares,
  get_group_signing_ctx
} from '@cmdcode/frost/lib'

import { get_record } from '@cmdcode/frost/util'

import type { PublicNonce, SecretNonce, SecretShare } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('Edge case: Threshold = n (all signers required)', t => {
    // 3-of-3: all signers must participate
    const threshold = 3
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    t.equal(group.shares.length, 3, 'Created 3 shares for 3-of-3')
    t.equal(group.vss_commits.length, 3, '3 VSS commits for threshold 3')

    // All shares should be valid
    for (const share of group.shares) {
      const is_valid = verify_share(group.vss_commits, share, threshold)
      t.true(is_valid, `Share ${share.idx} is valid`)
    }

    // Sign with all 3 participants
    const message = Buff.str('all signers test').hex
    const commits = group.shares.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    const psigs = group.shares.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)
    const is_valid = verify_final_sig(ctx, ctx.message, signature)

    t.true(is_valid, '3-of-3 signature is valid')
    t.equal(signature.length, 128, 'Signature has correct length')
    t.end()
  })

  tape.test('Edge case: Sparse indices [1, 3, 5] work correctly', t => {
    // Create 5 shares but only use indices 1, 3, 5
    const threshold = 2
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    // Select sparse set of signers
    const signers = [
      get_record(group.shares, 1),
      get_record(group.shares, 3),
      get_record(group.shares, 5)
    ]

    t.equal(signers.length, 3, 'Selected 3 signers with sparse indices')
    t.equal(signers[0].idx, 1, 'First signer has idx 1')
    t.equal(signers[1].idx, 3, 'Second signer has idx 3')
    t.equal(signers[2].idx, 5, 'Third signer has idx 5')

    // Verify all selected shares are valid
    for (const share of signers) {
      const is_valid = verify_share(group.vss_commits, share, threshold)
      t.true(is_valid, `Share ${share.idx} verifies`)
    }

    // Sign with sparse indices (only need 2 of 5 for threshold 2)
    const message = Buff.str('sparse indices test').hex
    const signing_subset = [signers[0], signers[2]] // indices 1 and 5

    const commits = signing_subset.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    const psigs = signing_subset.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)
    const is_valid = verify_final_sig(ctx, ctx.message, signature)

    t.true(is_valid, 'Signing with sparse indices [1, 5] produces valid signature')
    t.end()
  })

  tape.test('Edge case: Input validation - create_dealer_set(0, 3) throws', t => {
    try {
      create_dealer_set(0, 3)
      t.fail('Should throw error for threshold 0')
    } catch (e: any) {
      t.ok(e.message.includes('threshold'), 'Error mentions threshold')
      t.ok(e.message.includes('at least 1') || e.message.includes('must be'), 'Error explains the constraint')
    }
    t.end()
  })

  tape.test('Edge case: Input validation - create_dealer_set(5, 3) throws', t => {
    try {
      create_dealer_set(5, 3) // threshold > share_max
      t.fail('Should throw error for threshold > share_max')
    } catch (e: any) {
      t.ok(e.message.includes('threshold') || e.message.includes('exceed'), 'Error mentions threshold issue')
    }
    t.end()
  })

  tape.test('Edge case: Input validation - create_shares([], 0) throws', t => {
    try {
      create_shares([1n], 0) // count = 0
      t.fail('Should throw error for count = 0')
    } catch (e: any) {
      t.ok(e.message.includes('count') || e.message.includes('at least 1'), 'Error mentions count constraint')
    }
    t.end()
  })

  tape.test('Edge case: Input validation - combine_set([]) throws', t => {
    const empty_shares: SecretShare[] = []

    try {
      combine_set(empty_shares)
      t.fail('Should throw error for empty shares array')
    } catch (e: any) {
      t.ok(e.message.includes('empty') || e.message.includes('cannot'), 'Error mentions empty array')
    }
    t.end()
  })

  tape.test('Edge case: 1-of-n threshold (single signer)', t => {
    // 1-of-5: any single signer can sign
    const threshold = 1
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    t.equal(group.shares.length, 5, 'Created 5 shares')
    t.equal(group.vss_commits.length, 1, '1 VSS commit for threshold 1')

    // Verify any share is valid
    const share = group.shares[2] // random choice
    const is_valid = verify_share(group.vss_commits, share, threshold)
    t.true(is_valid, 'Single share verifies')

    // Sign with just one participant
    const message = Buff.str('single signer test').hex
    const commit = create_commit_pkg(share)
    const pnonces: PublicNonce[] = [{
      idx: commit.idx,
      hidden_pn: commit.hidden_pn,
      binder_pn: commit.binder_pn
    }]

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    const snonce: SecretNonce = {
      idx: commit.idx,
      hidden_sn: commit.hidden_sn,
      binder_sn: commit.binder_sn
    }
    const psig = sign_msg(ctx, share, snonce)

    const signature = combine_partial_sigs(ctx, [psig])
    const sig_valid = verify_final_sig(ctx, ctx.message, signature)

    t.true(sig_valid, '1-of-5 signature is valid')
    t.end()
  })

  tape.test('Edge case: Maximum practical threshold (20-of-20)', t => {
    // Test with a larger threshold where all must participate
    const threshold = 20
    const share_max = 20
    const group = create_dealer_set(threshold, share_max)

    t.equal(group.shares.length, 20, 'Created 20 shares')
    t.equal(group.vss_commits.length, 20, '20 VSS commits')

    // Verify random shares
    const share_5 = group.shares[4]
    const share_15 = group.shares[14]

    t.true(verify_share(group.vss_commits, share_5, threshold), 'Share 5 verifies')
    t.true(verify_share(group.vss_commits, share_15, threshold), 'Share 15 verifies')

    // Sign with all 20
    const message = Buff.str('large threshold test').hex
    const commits = group.shares.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    const psigs = group.shares.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)
    const is_valid = verify_final_sig(ctx, ctx.message, signature)

    t.true(is_valid, '20-of-20 signature is valid')
    t.end()
  })

  tape.test('Edge case: Different signer subsets produce same-verifying signatures', t => {
    // For 2-of-4, signing with {1,2} vs {3,4} should both verify
    const threshold = 2
    const share_max = 4
    const group = create_dealer_set(threshold, share_max)
    const message = Buff.str('subset test').hex

    // Sign with shares 1 and 2
    const subset_a = [group.shares[0], group.shares[1]]
    const commits_a = subset_a.map(s => create_commit_pkg(s))
    const pnonces_a: PublicNonce[] = commits_a.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx_a = get_group_signing_ctx(group.group_pk, pnonces_a, message)
    const psigs_a = subset_a.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits_a[i].idx,
        hidden_sn: commits_a[i].hidden_sn,
        binder_sn: commits_a[i].binder_sn
      }
      return sign_msg(ctx_a, share, snonce)
    })
    const sig_a = combine_partial_sigs(ctx_a, psigs_a)

    // Sign with shares 3 and 4
    const subset_b = [group.shares[2], group.shares[3]]
    const commits_b = subset_b.map(s => create_commit_pkg(s))
    const pnonces_b: PublicNonce[] = commits_b.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx_b = get_group_signing_ctx(group.group_pk, pnonces_b, message)
    const psigs_b = subset_b.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits_b[i].idx,
        hidden_sn: commits_b[i].hidden_sn,
        binder_sn: commits_b[i].binder_sn
      }
      return sign_msg(ctx_b, share, snonce)
    })
    const sig_b = combine_partial_sigs(ctx_b, psigs_b)

    // Both signatures should verify against the same group pubkey
    const valid_a = verify_final_sig(ctx_a, ctx_a.message, sig_a)
    const valid_b = verify_final_sig(ctx_b, ctx_b.message, sig_b)

    t.true(valid_a, 'Signature from subset {1,2} is valid')
    t.true(valid_b, 'Signature from subset {3,4} is valid')
    t.equal(ctx_a.group_pk, ctx_b.group_pk, 'Both contexts have same group pubkey')
    t.end()
  })
}
