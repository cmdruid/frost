import { random_bytes } from '@cmdcode/frost/util'

import {
  create_key_group,
  gen_recovery_shares,
  get_pubkey,
  get_share,
  recover_share
} from '@cmdcode/frost/lib'

import { aggregate_shares } from '../src/lib/util.js'

const seckey = random_bytes(32).hex
const pubkey = get_pubkey(seckey)

console.log('master pk:', pubkey)

const secrets  = [ seckey ]
const share_ct = 3
const thold    = 2

// Generate a secret, package of shares, and group key.
const group = create_key_group(thold, share_ct, secrets)

console.log('group pk:', group.pubkey)

// Distribute the shares.
const share_1 = get_share(group.shares, 1)
const share_2 = get_share(group.shares, 2)
const share_3 = get_share(group.shares, 3)

// Define the members involved in recovery.
const mbrs = [ 2, 3 ]

// Generate recovery shares from each member.
const mbr_2_rec  = gen_recovery_shares(mbrs, share_2, 1, thold)
const mbr_3_rec  = gen_recovery_shares(mbrs, share_3, 1, thold)
const rec_shares = [ mbr_2_rec.shares, mbr_3_rec.shares ]

// Distribute and aggregate the recovery shares from each member.
const mbr_2_agg  = aggregate_shares(rec_shares, 2)
const mbr_3_agg  = aggregate_shares(rec_shares, 3)
const agg_shares = [ mbr_2_agg, mbr_3_agg ]

// Provide the aggregate recovery shares to the target participant.
const repair_share = recover_share(agg_shares, 1)

console.log('repair share:', repair_share)
console.log('origin share:', share_1)
