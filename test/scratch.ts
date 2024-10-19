import { Buff }   from '@cmdcode/buff'
import { assert } from '@/index.js'

import {
  create_share_package,
  combine_secret_shares,
  verify_share_commit,
  derive_group_share
} from '@/shares.js'

const aliases = [ 'alice', 'bob', 'carol', 'david', 'edward', 'frank', 'gerome' ]

const pkgs = aliases.map(alias => {
  // Use hash of alias to create the root secret.
  const secret = Buff.str(alias).digest
  // Create a share package for the user.
  const shares = create_share_package([ secret ], 5, 7)
  // Verify each share is included in the polynomial.
  shares.sec_shares.forEach(s => {
    const is_valid = verify_share_commit(shares.vss_commits, s, 5)
    assert.ok(is_valid, 'share failed validation')
  })
  // shares.sec_shares = shares.sec_shares
  // Return the share package for the user.
  return shares
})

console.log('pkgs:')
console.dir(pkgs, { depth : null })

let gshares = aliases.map((_, idx) => {
  // Collect a share from each package at the given index.
  const shares = pkgs.map(pkg => pkg.sec_shares[idx])
  // Derive a group share and return.
  return derive_group_share(shares)
})

console.log('gshares:', gshares)

// Derive the group secret from the shares.
const secret = combine_secret_shares(gshares.slice(0, 5))

console.log('group secret:', secret)

// Stress test secret derivation using randomized order.
for (let i = 0; i < 20; i++) {
  gshares = gshares.sort(() => Math.random() - 0.5)
  console.log(gshares)
  const s2 = combine_secret_shares(gshares.slice(0, 5))
  console.log('s2:', s2)
  assert.ok(secret === s2, 'secret does not match control')
}

console.log('test passed')
