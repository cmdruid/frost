import { Test } from 'tape'

import { random_bytes } from '@cmdcode/frost/util'

import {
  combine_partial_sigs,
  create_commit_pkg,
  create_dealer_set,
  get_commit_pkg,
  get_group_signing_ctx,
  sign_msg,
  verify_final_sig,
  verify_partial_sig
} from '@cmdcode/frost/lib'

export default function (t : Test) {
  t.test('Test key and signature tweaking', t => {
    
    const tweaks: string[] = [
      random_bytes(32).hex,
      random_bytes(32).hex,
      random_bytes(32).hex,
      random_bytes(32).hex
    ]

    const secrets  = [ random_bytes(32), random_bytes(32) ]
    const message  = random_bytes(32).hex
    const thold    = 2
    const share_ct = 3
    const seed_h   = secrets[0].hex
    const seed_b   = secrets[1].hex

    try {
      // Generate a secret, package of shares, and group key.
      const group = create_dealer_set(thold, share_ct, secrets)

      // Use a t amount of shares to create nonce commitments.
      const shares  = group.shares.slice(0, thold)
      const commits = shares.map(e => create_commit_pkg(e, seed_h, seed_b))

      // Compute some context data for the signing session.
      const ctx = get_group_signing_ctx(group.group_pk, commits, message, tweaks)
      const idx = ctx.indexes.map(i => Number(i) - 1)

      // Create the partial signatures for a given signing context.
      const psigs = idx.map(i => {
        const share  = shares[i]
        const commit = get_commit_pkg(commits, share)
        const sig    = sign_msg(ctx, share, commit)
        if (!verify_partial_sig(ctx, commit, sig.pubkey, sig.psig)) {
          throw new Error('sig share failed validation')
        }
        return sig
      })

      // Aggregate the partial signatures into a single signature.
      const signature = combine_partial_sigs(ctx, psigs)
      const is_valid  = verify_final_sig(ctx, message, signature)

      if (!is_valid) {
        throw new Error('final signature failed validation')
      }

      t.pass('signature passes validation')

    } catch (err) {
      console.error(err)
      t.fail('test failed')
    }
    t.end()
  })
}
