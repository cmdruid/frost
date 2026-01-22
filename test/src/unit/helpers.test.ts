import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  generate_seckey,
  tweak_seckey,
  tweak_pubkey,
  convert_pubkey,
  get_pubkey,
  merge_shares,
  merge_share_commits,
  verify_share,
  create_share_set
} from '@cmdcode/frost/lib'

import type { SecretShare } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('Helpers: merge_shares pairwise combination', t => {
    const threshold = 2
    const share_max = 3

    // Create two share sets (simulating two DKG dealers)
    const set_a = create_share_set(threshold, share_max)
    const set_b = create_share_set(threshold, share_max)

    // Merge the shares
    const merged = merge_shares(set_a.shares, set_b.shares)

    t.equal(merged.length, share_max, 'Merged shares has correct length')

    // Verify indices are preserved
    for (let i = 0; i < merged.length; i++) {
      t.equal(merged[i].idx, set_a.shares[i].idx, `Merged share ${i} has correct idx`)
    }

    // Verify the merged seckey is the sum of the original seckeys
    for (let i = 0; i < merged.length; i++) {
      const a_big = Buff.hex(set_a.shares[i].seckey).big
      const b_big = Buff.hex(set_b.shares[i].seckey).big
      const expected_sum = (a_big + b_big) % BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
      const merged_big = Buff.hex(merged[i].seckey).big
      t.equal(merged_big, expected_sum, `Merged share ${i} is sum of originals`)
    }
    t.end()
  })

  tape.test('Helpers: merge_share_commits VSS commit merging', t => {
    const threshold = 2
    const share_max = 3

    const set_a = create_share_set(threshold, share_max)
    const set_b = create_share_set(threshold, share_max)

    // Merge the VSS commits
    const merged_commits = merge_share_commits(set_a.vss_commits, set_b.vss_commits)

    t.equal(merged_commits.length, threshold, 'Merged commits has correct length')

    // Each merged commit should be 33 bytes (compressed pubkey)
    for (const commit of merged_commits) {
      t.equal(Buff.hex(commit).length, 33, 'Merged commit is 33 bytes')
    }

    // Merge shares and verify against merged commits
    const merged_shares = merge_shares(set_a.shares, set_b.shares)
    const is_valid = verify_share(merged_commits, merged_shares[0], threshold)
    t.true(is_valid, 'Merged share verifies against merged commits')
    t.end()
  })

  tape.test('Helpers: generate_seckey produces valid 32-byte keys', t => {
    // Test random generation
    const key1 = generate_seckey()
    const key2 = generate_seckey()

    t.equal(key1.length, 32, 'Generated key is 32 bytes')
    t.equal(key2.length, 32, 'Second generated key is 32 bytes')
    t.notEqual(key1.hex, key2.hex, 'Two generated keys are different')

    // Test deterministic generation with aux input
    const aux = Buff.str('deterministic seed')
    const det_key1 = generate_seckey(aux)
    const det_key2 = generate_seckey(aux)

    t.equal(det_key1.length, 32, 'Deterministic key is 32 bytes')
    t.equal(det_key1.hex, det_key2.hex, 'Same aux produces same key')

    // Verify keys can be used to derive valid pubkeys
    const pubkey = get_pubkey(key1)
    t.equal(Buff.hex(pubkey).length, 33, 'Can derive 33-byte pubkey from generated key')
    t.end()
  })

  tape.test('Helpers: tweak_seckey correctness', t => {
    const seckey = Buff.random(32)
    const tweak = Buff.random(32)

    const tweaked = tweak_seckey(seckey, tweak)

    // Verify result is 32 bytes hex
    t.equal(Buff.hex(tweaked).length, 32, 'Tweaked seckey is 32 bytes')

    // Verify it's different from original (with overwhelming probability)
    t.notEqual(tweaked, seckey.hex, 'Tweaked key differs from original')

    // Tweak with identity (1) should preserve key modulo N
    const identity = Buff.big(1n, 32)
    const identity_tweaked = tweak_seckey(seckey, identity)
    const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
    const expected = seckey.big % N
    t.equal(Buff.hex(identity_tweaked).big, expected, 'Tweak by 1 preserves key (mod N)')
    t.end()
  })

  tape.test('Helpers: tweak_pubkey correctness', t => {
    const seckey = Buff.random(32).hex
    const pubkey = get_pubkey(seckey)
    const tweak = Buff.random(32).hex

    const tweaked_pk = tweak_pubkey(pubkey, tweak)

    // Verify result is 33 bytes hex
    t.equal(Buff.hex(tweaked_pk).length, 33, 'Tweaked pubkey is 33 bytes')

    // Verify tweak_pubkey(pk, t) == get_pubkey(tweak_seckey(sk, t))
    const tweaked_sk = tweak_seckey(seckey, tweak)
    const expected_pk = get_pubkey(tweaked_sk)
    t.equal(tweaked_pk, expected_pk, 'tweak_pubkey matches get_pubkey(tweak_seckey())')

    // Test with 32-byte x-only input
    const xonly_pk = Buff.hex(pubkey).slice(1).hex
    const tweaked_xonly = tweak_pubkey(xonly_pk, tweak)
    t.equal(Buff.hex(tweaked_xonly).length, 33, 'Tweaking x-only pubkey returns 33 bytes')
    t.end()
  })

  tape.test('Helpers: convert_pubkey 32/33 byte handling', t => {
    const seckey = Buff.random(32).hex
    const pubkey_33 = get_pubkey(seckey) // 33 bytes (compressed)
    const pubkey_32 = Buff.hex(pubkey_33).slice(1).hex // 32 bytes (x-only)

    // Convert 33-byte to ECDSA (should stay 33)
    const ecdsa_from_33 = convert_pubkey(pubkey_33, 'ecdsa')
    t.equal(Buff.hex(ecdsa_from_33).length, 33, '33-byte to ECDSA stays 33 bytes')
    t.equal(ecdsa_from_33, pubkey_33, '33-byte to ECDSA is unchanged')

    // Convert 32-byte to ECDSA (should become 33)
    const ecdsa_from_32 = convert_pubkey(pubkey_32, 'ecdsa')
    t.equal(Buff.hex(ecdsa_from_32).length, 33, '32-byte to ECDSA becomes 33 bytes')
    t.equal(Buff.hex(ecdsa_from_32)[0], 0x02, 'Prepends 0x02 prefix')

    // Convert 33-byte to BIP340 (should become 32)
    const bip340_from_33 = convert_pubkey(pubkey_33, 'bip340')
    t.equal(Buff.hex(bip340_from_33).length, 32, '33-byte to BIP340 becomes 32 bytes')
    t.equal(bip340_from_33, pubkey_32, '33-byte to BIP340 matches x-only')

    // Convert 32-byte to BIP340 (should stay 32)
    const bip340_from_32 = convert_pubkey(pubkey_32, 'bip340')
    t.equal(Buff.hex(bip340_from_32).length, 32, '32-byte to BIP340 stays 32 bytes')
    t.equal(bip340_from_32, pubkey_32, '32-byte to BIP340 is unchanged')

    // Round-trip test
    const roundtrip = convert_pubkey(convert_pubkey(pubkey_33, 'bip340'), 'ecdsa')
    t.equal(Buff.hex(roundtrip).slice(1).hex, pubkey_32, 'Round-trip preserves x-coordinate')
    t.end()
  })

  tape.test('Helpers: convert_pubkey throws on invalid type', t => {
    const pubkey = get_pubkey(Buff.random(32).hex)

    try {
      // @ts-ignore - intentionally passing invalid type
      convert_pubkey(pubkey, 'invalid')
      t.fail('Should throw error for invalid type')
    } catch (e: any) {
      t.ok(e.message.includes('invalid'), 'Error message mentions invalid type')
    }
    t.end()
  })
}
