import { Buff }                   from '@cmdcode/buff'
import { get_pubkey, get_seckey } from '@cmdcode/crypto-tools/keys'
import { generate_dealer_pkg }    from '@/lib/pkg.js'

import { decode_group_pkg, decode_secret_pkg, encode_group_pkg, encode_secret_pkg } from '@/lib/encoder.js'

const secret = Buff.random(32)
const seckey = get_seckey(secret).hex
const pubkey = get_pubkey(seckey, true).hex

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
