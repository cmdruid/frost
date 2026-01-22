import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  create_commit_pkg,
  sign_msg,
  verify_partial_sig,
  combine_partial_sigs,
  verify_share,
  get_group_signing_ctx,
  get_pubkey,
  verify_final_sig
} from '@cmdcode/frost/lib'

import type { PublicNonce, SecretNonce } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('Security: Invalid commitment detection (wrong public nonce)', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('security test').hex
    const signers = [group.shares[0], group.shares[1]]

    // Create valid commitments
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

    // Create tampered public nonce (different from what was committed)
    const tampered_nonce: PublicNonce = {
      idx: pnonces[0].idx,
      hidden_pn: get_pubkey(Buff.random(32).hex), // Wrong nonce
      binder_pn: pnonces[0].binder_pn
    }

    // Verification should fail with tampered nonce
    const correct_pk = get_pubkey(signers[0].seckey)
    const is_valid = verify_partial_sig(ctx, tampered_nonce, correct_pk, psig.psig)

    t.false(is_valid, 'Partial sig verification fails with tampered public nonce')
    t.end()
  })

  tape.test('Security: Invalid partial signature detection (tampered psig)', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('tamper test').hex
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

    // Tamper with the partial signature by flipping bits
    const psig_bytes = Buff.hex(psig.psig)
    const tampered_bytes = new Buff(new Uint8Array([
      ...psig_bytes.slice(0, 16),
      psig_bytes[16] ^ 0xff, // Flip byte
      ...psig_bytes.slice(17)
    ]))
    const tampered_psig = tampered_bytes.hex

    const correct_pk = get_pubkey(signers[0].seckey)
    const is_valid = verify_partial_sig(ctx, pnonces[0], correct_pk, tampered_psig)

    t.false(is_valid, 'Partial sig verification fails with tampered psig')
    t.end()
  })

  tape.test('Security: Share tampering detection via VSS verification', t => {
    const threshold = 3
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    // Verify original shares are valid
    for (const share of group.shares) {
      const is_valid = verify_share(group.vss_commits, share, threshold)
      t.true(is_valid, `Original share ${share.idx} is valid`)
    }

    // Tamper with a share's secret key
    const tampered_share = {
      idx: group.shares[0].idx,
      seckey: Buff.random(32).hex // Random key, not the real one
    }

    const is_valid = verify_share(group.vss_commits, tampered_share, threshold)
    t.false(is_valid, 'Tampered share fails VSS verification')
    t.end()
  })

  tape.test('Security: Combined signature validity after aggregation', t => {
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    const message = Buff.str('aggregation test').hex
    const signers = [group.shares[0], group.shares[1]]

    const commits = signers.map(s => create_commit_pkg(s))
    const pnonces: PublicNonce[] = commits.map(c => ({
      idx: c.idx,
      hidden_pn: c.hidden_pn,
      binder_pn: c.binder_pn
    }))

    const ctx = get_group_signing_ctx(group.group_pk, pnonces, message)

    const psigs = signers.map((share, i) => {
      const snonce: SecretNonce = {
        idx: commits[i].idx,
        hidden_sn: commits[i].hidden_sn,
        binder_sn: commits[i].binder_sn
      }
      return sign_msg(ctx, share, snonce)
    })

    const signature = combine_partial_sigs(ctx, psigs)

    // Verify the final signature
    const is_valid = verify_final_sig(ctx, ctx.message, signature)
    t.true(is_valid, 'Combined signature is valid')

    // Tamper with signature and verify it fails
    const sig_bytes = Buff.hex(signature)
    const tampered_sig_bytes = new Buff(new Uint8Array([
      ...sig_bytes.slice(0, 32),
      sig_bytes[32] ^ 0xff, // Flip byte in s portion
      ...sig_bytes.slice(33)
    ]))
    const tampered_sig = tampered_sig_bytes.hex

    const tampered_valid = verify_final_sig(ctx, ctx.message, tampered_sig)
    t.false(tampered_valid, 'Tampered combined signature fails verification')
    t.end()
  })
}
