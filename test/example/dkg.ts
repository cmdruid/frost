import { Buff }   from '@cmdcode/buff'
import { assert } from '@cmdcode/frost/util'

import {
  derive_secret,
  combine_set,
  create_key_group
} from '@cmdcode/frost/lib'

const aliases = [ 'alice', 'bob', 'carol', 'david', 'edward', 'frank', 'gerome' ]
const target  = '1353adcaf8f428bc77e61f83261dca4b6697c45ad5a35b0ea591dc13ecb7dca1'

/**
 * All users agree on terms for creating a polynomial,
 * then each user creates their own unique polynomial.
 */
const groups = aliases.map(alias => {
  // Use hash of alias to create the root secret.
  const secret  = Buff.str(alias).digest
  // Create a share package for the user.
  const group = create_key_group(5, 7, [ secret ])
  // Return the share package for the user.
  return group
})

/**
 * All users agree on an index value for each user, then
 * each user distributes a share of their polynomial to
 * other users, based on their assigned index.
 */
let gshares = aliases.map((_, idx) => {
  // Collect a share from each package at the given index.
  const shares = groups.map(group => group.shares[idx])
  // Derive a group share and return.
  return combine_set(shares)
})

/**
 * All users now have a unique aggregate share of an unknown
 * group secret, with each share known only to the user at index.
 */
const secret = derive_secret(gshares.slice(0, 5))

assert.ok(secret === target, 'secret does not match target')
