import { Buff, Bytes }     from '@cmdcode/buff'
import { G, H }            from '@/ecc/index.js'
import { lift_x, mod_n }          from '@/ecc/util.js'
import { _0n, _1n }        from '@/const.js'
import { assert, hash340 } from '@/util/index.js'

/**
 * Generates a secret key.
 */
export function generate_seckey (
  aux ?: Bytes
) : Buff {
  const aux_bytes = (aux !== undefined)
    ? Buff.bytes(aux, 32)
    : Buff.random(32)
  return H.H3(aux_bytes)
}

/**
 * Generates a secret nonce using a secret key, and optional auxiliary value.
 */
export function generate_nonce (
  secret    : Bytes,
  aux_seed ?: Bytes
) : Buff {
  const aux = (aux_seed !== undefined)
    ? Buff.bytes(aux_seed, 32)
    : Buff.random(32)
  const secret_seed  = Buff.join([ aux, secret ])
  return H.H3(secret_seed)
}

export function tweak_seckey (
  seckey : Bytes,
  tweak  : Bytes
) {
  const coeff   = Buff.bytes(tweak).big 
  const secret  = Buff.bytes(seckey).big
  const tweaked = mod_n(secret * coeff)
  return Buff.big(tweaked).hex
}

export function get_pubkey (secret : Bytes) {
  const scalar = Buff.bytes(secret).big
  const point  = G.ScalarBaseMulti(scalar)
  return G.SerializeElement(point).hex
}

export function tweak_pubkey (
  pubkey : Bytes,
  tweak  : Bytes
) {
  const coeff = Buff.bytes(tweak).big
  let   point = lift_x(pubkey)
        point = point.multiply(coeff)
  return G.SerializeElement(point).hex
}

/**
 * Computes a BIP340 compatible challenge message.
 */
export function get_challenge (
  pnonce  : Bytes,
  pubkey  : Bytes,
  message : Bytes
) {
  const grp_pk = convert_pubkey(pubkey, 'bip340')
  const grp_pn = convert_pubkey(pnonce, 'bip340')
  assert.size(grp_pk, 32)
  assert.size(grp_pn, 32)
  const digest = hash340('BIP0340/challenge', grp_pn, grp_pk, message)
  return digest.big
}

export function convert_pubkey (
  pubkey : Bytes,
  type   : 'ecdsa' | 'bip340'
) : string {
  const pub = Buff.bytes(pubkey)
  if (type === 'ecdsa') {
    return pub.length === 32
      ? pub.prepend(2).hex
      : pub.hex
  } else if (type === 'bip340') {
    return (pub.length === 33)
      ? pub.slice(1).hex
      : pub.hex
  } else {
    throw new Error('invalid pubkey type')
  }
}