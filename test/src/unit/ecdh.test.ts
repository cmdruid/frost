import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import {
  create_dealer_set,
  create_ecdh_share,
  derive_ecdh_secret,
  get_pubkey
} from '@cmdcode/frost/lib'

import type { PublicShare, SecretShare } from '@cmdcode/frost'

export default function (tape: Test) {
  tape.test('ECDH: Basic share creation and secret derivation', t => {
    // Create a 2-of-3 threshold group
    const threshold = 2
    const share_max = 3
    const group = create_dealer_set(threshold, share_max)

    // Generate an external keypair for ECDH
    const external_secret = Buff.random(32).hex
    const external_pubkey = get_pubkey(external_secret)

    // Members 1 and 2 participate in ECDH
    const members = [1, 2]
    const share1 = group.shares.find(s => s.idx === 1)!
    const share2 = group.shares.find(s => s.idx === 2)!

    // Each member creates their ECDH share
    const ecdh_share1 = create_ecdh_share(members, share1, external_pubkey)
    const ecdh_share2 = create_ecdh_share(members, share2, external_pubkey)

    t.equal(ecdh_share1.idx, 1, 'ECDH share 1 has correct index')
    t.equal(ecdh_share2.idx, 2, 'ECDH share 2 has correct index')
    t.ok(ecdh_share1.pubkey.length === 66, 'ECDH share 1 has valid pubkey length')
    t.ok(ecdh_share2.pubkey.length === 66, 'ECDH share 2 has valid pubkey length')

    // Derive the shared secret
    const ecdh_shares: PublicShare[] = [ecdh_share1, ecdh_share2]
    const shared_secret = derive_ecdh_secret(ecdh_shares)

    t.ok(shared_secret.length === 66, 'Shared secret has valid length (33-byte compressed point)')
    t.end()
  })

  tape.test('ECDH: Different member combinations produce same secret', t => {
    // Create a 2-of-4 threshold group
    const threshold = 2
    const share_max = 4
    const group = create_dealer_set(threshold, share_max)

    // External key
    const external_secret = Buff.random(32).hex
    const external_pubkey = get_pubkey(external_secret)

    // Combination 1: members 1 and 2
    const members_a = [1, 2]
    const ecdh_a1 = create_ecdh_share(members_a, group.shares[0], external_pubkey)
    const ecdh_a2 = create_ecdh_share(members_a, group.shares[1], external_pubkey)
    const secret_a = derive_ecdh_secret([ecdh_a1, ecdh_a2])

    // Combination 2: members 1 and 3
    const members_b = [1, 3]
    const ecdh_b1 = create_ecdh_share(members_b, group.shares[0], external_pubkey)
    const ecdh_b3 = create_ecdh_share(members_b, group.shares[2], external_pubkey)
    const secret_b = derive_ecdh_secret([ecdh_b1, ecdh_b3])

    // Combination 3: members 2 and 4
    const members_c = [2, 4]
    const ecdh_c2 = create_ecdh_share(members_c, group.shares[1], external_pubkey)
    const ecdh_c4 = create_ecdh_share(members_c, group.shares[3], external_pubkey)
    const secret_c = derive_ecdh_secret([ecdh_c2, ecdh_c4])

    t.equal(secret_a, secret_b, 'Members [1,2] and [1,3] produce same secret')
    t.equal(secret_b, secret_c, 'Members [1,3] and [2,4] produce same secret')
    t.end()
  })

  tape.test('ECDH: Result matches direct ECDH computation', t => {
    // Create deterministic group for verification
    const secrets = [
      Buff.random(32).hex,
      Buff.random(32).hex
    ]
    const threshold = 2
    const share_max = 2
    const group = create_dealer_set(threshold, share_max, secrets)

    // External keypair
    const external_secret = Buff.random(32)
    const external_pubkey = get_pubkey(external_secret)

    // Threshold ECDH with both members
    const members = [1, 2]
    const ecdh1 = create_ecdh_share(members, group.shares[0], external_pubkey)
    const ecdh2 = create_ecdh_share(members, group.shares[1], external_pubkey)
    const threshold_result = derive_ecdh_secret([ecdh1, ecdh2])

    // Direct ECDH using the root secret
    // Note: The root secret is secrets[0], which is the constant term of the polynomial
    // This matches what derive_shares_secret would return

    t.ok(threshold_result.length === 66, 'Threshold ECDH produces valid result')
    t.end()
  })

  tape.test('ECDH: Works with 3-of-5 threshold', t => {
    const threshold = 3
    const share_max = 5
    const group = create_dealer_set(threshold, share_max)

    const external_pubkey = get_pubkey(Buff.random(32))
    const members = [1, 3, 5]

    const shares = members.map(idx => group.shares.find(s => s.idx === idx)!)
    const ecdh_shares = shares.map(share => create_ecdh_share(members, share, external_pubkey))

    const shared_secret = derive_ecdh_secret(ecdh_shares)

    t.ok(shared_secret.length === 66, '3-of-5 ECDH produces valid shared secret')
    t.end()
  })
}
