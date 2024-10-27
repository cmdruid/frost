// Create a set of shares.

import { Buff } from '@cmdcode/buff'

import { combine_partial_sigs, create_dealer_pkg, create_psig_pkg, decode_group_pkg, decode_secret_pkg, encode_group_pkg, encode_secret_pkg, get_package_ctx, get_pubkey, get_session_ctx, verify_final_sig, verify_psig_pkg } from '@bifrost/lib'

const seckey  = Buff.random(32).hex
const pubkey  = get_pubkey(seckey)
const message = Buff.random(32).hex 

console.log(seckey)
console.log(message)
console.log('master pubkey:', pubkey)

const pkg = create_dealer_pkg([ seckey ], 2, 3)

console.log('pkg:', pkg)

const encoded_group   = encode_group_pkg(pkg)

console.log('group:', encoded_group)

const encoded_secrets = pkg.secrets.map(e => encode_secret_pkg(e))

console.log('secrets:', encoded_secrets)

const decoded_group   = decode_group_pkg(encoded_group)
const decoded_secrets = encoded_secrets.map(e => decode_secret_pkg(e))

const ctx     = get_package_ctx(decoded_group, message)
const signer1 = decoded_secrets[0]
const signer2 = decoded_secrets[2]

const psig1   = create_psig_pkg(ctx, signer1)
const psig2   = create_psig_pkg(ctx, signer2)

console.log('psig1 valid:', verify_psig_pkg(ctx, psig1))
console.log('psig2 valid:', verify_psig_pkg(ctx, psig2))

const sig = combine_partial_sigs(ctx, [ psig1, psig2 ])

console.log('final sig valid:', verify_final_sig(ctx, message, sig))
