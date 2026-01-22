import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  create_commit_pkg,
  sign_msg,
  verify_partial_sig,
  combine_partial_sigs,
  create_shares,
  verify_share,
  get_group_signing_ctx,
  get_group_key_context,
  get_pubkey
} from '@cmdcode/frost/lib'

import { get_record } from '@cmdcode/frost/util'

import type { PublicNonce, SecretNonce, SecretShare } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('Errors: sign_msg with mismatched nonce/share indices', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('test').hex
    const signers = [group.shares[0], group.shares[1]]

    // Create commitments
    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    // Try to sign with mismatched indices (share 1 with nonce from share 2)
    const share = group.shares[0] // idx = 1
    const wrong_nonce: SecretNonce = {
      idx: 2, // Wrong index!
      hidden_sn: commits[1].hidden_sn,
      binder_sn: commits[1].binder_sn
    }

    try {
      sign_msg(ctx, share, wrong_nonce)
      t.fail('Should throw error for mismatched nonce/share indices')
    } catch (e: any) {
      t.ok(e.message.includes('index'), 'Error mentions index mismatch')
    }
    t.end()
  })

  tape.test('Errors: verify_partial_sig with wrong pubkey', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('test').hex
    const signers = [group.shares[0], group.shares[1]]

    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    // Create valid partial signature
    const snonce: SecretNonce = {
      idx: commits[0].idx,
      hidden_sn: commits[0].hidden_sn,
      binder_sn: commits[0].binder_sn
    }
    const psig = sign_msg(ctx, signers[0], snonce)

    // Use wrong pubkey (from share 3, not share 1)
    const wrong_pk = get_pubkey(group.shares[2].seckey)

    const is_valid = verify_partial_sig(ctx, pnonces[0], wrong_pk, psig.psig)
    t.false(is_valid, 'Partial sig verification fails with wrong pubkey')
    t.end()
  })

  tape.test('Errors: get_record with missing index', t => {
    const shares: SecretShare[] = [
      { idx: 1, seckey: 'abc' },
      { idx: 2, seckey: 'def' }
    ]

    try {
      get_record(shares, 5) // Index 5 doesn't exist
      t.fail('Should throw error for missing index')
    } catch (e) {
      t.pass('Throws error when index not found')
    }
    t.end()
  })

  tape.test('Errors: Invalid pubkey length in get_group_key_context', t => {
    const short_key = Buff.random(20).hex // Too short
    const long_key = Buff.random(40).hex  // Too long

    try {
      get_group_key_context(short_key)
      t.fail('Should throw error for short pubkey')
    } catch (e: any) {
      t.ok(e.message.includes('invalid'), 'Error for short pubkey')
    }

    try {
      get_group_key_context(long_key)
      t.fail('Should throw error for long pubkey')
    } catch (e: any) {
      t.ok(e.message.includes('invalid'), 'Error for long pubkey')
    }
    t.end()
  })

  tape.test('Errors: verify_share with wrong threshold', t => {
    const threshold = 3
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    // Verify with wrong threshold (2 instead of 3)
    // This should fail because we're not using all required commits
    const share = group.shares[0]

    // Using threshold 2 (one less commit than needed)
    const is_valid = verify_share(group.vss_commits, share, 2)
    t.false(is_valid, 'Share verification fails with wrong threshold')
    t.end()
  })

  tape.test('Edge case: Minimum threshold (2-of-2)', t => {
    const threshold = 2
    const share_max = 2
    const group = create_dealer_set(threshold, share_max)

    t.equal(group.shares.length, 2, 'Created 2 shares for 2-of-2')
    t.equal(group.vss_commits.length, 2, '2 VSS commits for threshold 2')

    // Both shares should be valid
    const valid_1 = verify_share(group.vss_commits, group.shares[0], threshold)
    const valid_2 = verify_share(group.vss_commits, group.shares[1], threshold)

    t.true(valid_1, 'Share 1 is valid')
    t.true(valid_2, 'Share 2 is valid')

    // Can sign with both shares
    const message = Buff.str('2-of-2 test').hex
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
    t.ok(signature.length === 128, '2-of-2 produces valid signature length')
    t.end()
  })

  tape.test('Edge case: Single tweak application', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('tweaked').hex
    const tweak = Buff.random(32).hex

    const signers = [group.shares[0], group.shares[1]]
    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    // Apply single tweak
    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message, [tweak])

    t.notEqual(ctx.group_pk, group.group_pk, 'Tweaked pubkey differs from original')

    const psigs = signers.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)
    t.ok(signature.length === 128, 'Single tweak signing produces valid signature')
    t.end()
  })

  tape.test('Edge case: Multiple tweaks', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('multi-tweak').hex
    const tweaks = [
      Buff.random(32).hex,
      Buff.random(32).hex,
      Buff.random(32).hex
    ]

    const signers = [group.shares[0], group.shares[1]]
    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    // Apply multiple tweaks
    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message, tweaks)

    const psigs = signers.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)
    t.ok(signature.length === 128, 'Multiple tweaks signing produces valid signature')
    t.end()
  })

  tape.test('Edge case: Empty tweak array', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('no tweaks').hex

    const signers = [group.shares[0], group.shares[1]]
    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    // Empty tweak array
    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message, [])

    t.equal(ctx.group_pk, group.group_pk, 'Empty tweaks keeps original pubkey')

    const psigs = signers.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)
    t.ok(signature.length === 128, 'Empty tweak array works correctly')
    t.end()
  })

  tape.test('Edge case: Large threshold (10-of-15)', t => {
    const threshold = 10
    const share_max = 15
    const group = create_dealer_set(threshold, share_max)

    t.equal(group.shares.length, 15, 'Created 15 shares')
    t.equal(group.vss_commits.length, 10, '10 VSS commits for threshold 10')

    // Verify random share
    const share = group.shares[7]
    const is_valid = verify_share(group.vss_commits, share, threshold)
    t.true(is_valid, 'Share verification works with large threshold')
    t.end()
  })
}
