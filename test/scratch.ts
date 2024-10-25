import { Buff }                   from '@cmdcode/buff'
import { get_pubkey, get_seckey } from '@cmdcode/crypto-tools/keys'

import {
  get_session_ctx,
  decode_group_pkg,
  decode_secret_pkg,
  encode_group_pkg,
  encode_secret_pkg,
  generate_dealer_pkg,
  sign_with_pkg,
  verify_sig_pkg,
  combine_partial_sigs,
  verify_final_sig
} from '@bifrost/lib'

const secret = Buff.random(32)
const seckey = get_seckey(secret).hex
const pubkey = get_pubkey(seckey).hex

console.log('seckey:', seckey)
console.log('pubkey:', pubkey)

const pkg = generate_dealer_pkg([ seckey ], 3, 2)

const grp_enc = encode_group_pkg(pkg.group)
const grp_sec = pkg.secrets.map(e => encode_secret_pkg(e))

console.log('Dealer Package:')
console.dir(pkg, { depth: null })

console.log('\nEncoded Group Package')
console.log(encode_group_pkg(pkg.group))

console.log('\nEncoded Secret Packages')
console.log(pkg.secrets.map(e => encode_secret_pkg(e)))


console.log('\nDecoded Group Package')
console.log(decode_group_pkg(grp_enc))

console.log('\nDecoded Secret Packages')
console.log(grp_sec.map(e => decode_secret_pkg(e)))

const msg = '56525e016c2ce9a33bac3ee22e4522448237287735e283ef8b49e387e8eacde3'

const { commits, group_pk } = pkg.group

const ctx   = get_session_ctx(group_pk, commits, msg)

const psig1 = sign_with_pkg(ctx, pkg.secrets[0])
const pk1   = get_pubkey(pkg.secrets[0].share_sk).hex
console.log('psig1 valid:', verify_sig_pkg(ctx, pk1, psig1))

const psig2 = sign_with_pkg(ctx, pkg.secrets[1])
const pk2   = get_pubkey(pkg.secrets[1].share_sk).hex
console.log('psig2 valid:', verify_sig_pkg(ctx, pk2, psig2))

const sig = combine_partial_sigs(ctx, [ psig1, psig2 ])

console.log('sig valid:', verify_final_sig(ctx, msg, sig))
