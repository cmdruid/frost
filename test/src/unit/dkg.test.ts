import { Test }   from 'tape'
import { Buff }   from '@cmdcode/buff'
import { assert } from '@cmdcode/frost/util'

import {
  create_share_pkg,
  derive_secret,
  verify_share,
  combine_shares
} from '@cmdcode/frost/lib'

const aliases = [ 'alice', 'bob', 'carol', 'david', 'edward', 'frank', 'gerome' ]
const target  = '1353adcaf8f428bc77e61f83261dca4b6697c45ad5a35b0ea591dc13ecb7dca1'

export default function (tape : Test) {

  tape.test('Testing distributed key generation', t => {

    try {
      const pkgs = aliases.map(alias => {
        // Use hash of alias to create the root secret.
        const secret = Buff.str(alias).digest
        // Create a share package for the user.
        const shares = create_share_pkg([ secret ], 5, 7)
        // Verify each share is included in the polynomial.
        shares.sec_shares.forEach(s => {
          const is_valid = verify_share(shares.vss_commits, s, 5)
          assert.ok(is_valid, 'share failed validation')
        })
        // Return the share package for the user.
        return shares
      })

      t.pass('participant share packages are valid')

      // Compute the group shares from each user polynomial.
      let gshares = aliases.map((_, idx) => {
        // Collect a share from each package at the given index.
        const shares = pkgs.map(pkg => pkg.sec_shares[idx])
        // Derive a group share and return.
        return combine_shares(shares)
      })

      // Derive the group secret from the shares.
      const secret = derive_secret(gshares.slice(0, 5))

      t.equal(secret, target, 'group secret matches target')

      // Stress test secret derivation using randomized order.
      for (let i = 0; i < 20; i++) {
        gshares = gshares.sort(() => Math.random() - 0.5)
        const s2 = derive_secret(gshares.slice(0, 5))
        assert.ok(secret === s2, 'secret does not match control')
      }

      t.pass('all randomized DKG tests passed')
      
    } catch (err) {
      t.fail('failed to generate share packages')
    }

    t.end()

  })
}
