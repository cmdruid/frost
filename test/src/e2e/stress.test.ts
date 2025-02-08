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

export default function (t : Test, rounds = 10, max_shares = 21) {
  t.test('Stress test the full protocol', t => {

    const failures : number[] = []

    for (let i = 0; i < rounds; i++) {

      const secrets  = [ random_bytes(32), random_bytes(32) ]
      const message  = random_bytes(32).hex
      const share_ct = get_random_rng(3, max_shares)
      const thold    = get_random_rng(2, share_ct - 2)
      const seed_h   = secrets[0].hex
      const seed_b   = secrets[1].hex

      try {
        // Generate a secret, package of shares, and group key.
        const group = create_dealer_set(thold, share_ct, secrets)

        // This part is really slow.

        // sec_shares.forEach(e => {
        //   if (!verify_share_commit(vss_commits, e, thold)) {
        //     console.log(`share ${e.idx}:, ${e.seckey}`)
        //     throw new Error('share failed validation')
        //   }
        // })

        // Use a t amount of shares to create nonce commitments.
        const shares  = group.shares.slice(0, thold)
        const commits = shares.map(e => create_commit_pkg(e, seed_h, seed_b))

        // Compute some context data for the signing session.
        const ctx = get_group_signing_ctx(group.group_pk, commits, message)
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

      } catch (err) {
        console.log('iteration:', i)
        console.log('share_min:', thold)
        console.log('share_max:', share_ct)
        console.error(err)
        failures.push(i)
      }
    }
    t.true(failures.length === 0, 'stress testing passed')
    t.end()
  })
}

function get_random_rng (min : number, max : number) {
  min = Math.ceil(min)
  max = Math.floor(max)
  return Math.floor(Math.random() * (max - min + 1) + min)
}
