import { random_bytes } from '@cmdcode/frost/util'

import {
  create_ecdh_share,
  create_dealer_set,
  derive_ecdh_secret,
  generate_seckey,
  get_pubkey,
  get_share,
  tweak_pubkey
} from '@cmdcode/frost/lib'

const seckey    = random_bytes(32).hex
const secrets   = [ seckey ]
const threshold = 2
const share_max = 3

const demo_seckey = generate_seckey()
const demo_pubkey = get_pubkey(demo_seckey)

// Generate a secret, package of shares, and group key.
const group   = create_dealer_set(threshold, share_max, secrets)

// Define the members of the scheme.
const members = [ 1, 3 ]

// Define the shares for each member.
const share_1 = get_share(group.shares, 1)
const share_3 = get_share(group.shares, 3)

// Create an ECDH share for each member.
const ecdh_share_1 = create_ecdh_share(members, share_1, demo_pubkey)
const ecdh_share_3 = create_ecdh_share(members, share_3, demo_pubkey)

// Derive the shared secret.
const mstr_shared_secret  = tweak_pubkey(demo_pubkey, seckey)
const demo_shared_secret  = tweak_pubkey(group.group_pk, demo_seckey)
const frost_shared_secret = derive_ecdh_secret([ ecdh_share_1, ecdh_share_3 ])

console.log('demo shared secret  :', mstr_shared_secret)
console.log('demo shared secret  :', demo_shared_secret)
console.log('frost_shared_secret :', frost_shared_secret)
