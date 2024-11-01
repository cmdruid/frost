import { Buff, Bytes } from '@cmdcode/buff'
import { hash340 }     from '@cmdcode/crypto-tools/hash'
import { H }           from '@/ecc/index.js'
import { _0n, _1n }    from '@/const.js'
import { assert }      from '@/util/index.js'

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

/**
 * Computes a BIP340 compatible challenge message.
 */
export function get_challenge (
  pnonce  : Bytes,
  pubkey  : Bytes,
  message : Bytes
) {
  const grp_pk = Buff.bytes(pubkey).slice(1)
  const grp_pn = Buff.bytes(pnonce).slice(1)
  assert.size(grp_pk, 32)
  assert.size(grp_pn, 32)
  return hash340('BIP0340/challenge', grp_pn, grp_pk, message).big
}
