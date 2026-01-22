/**
 * @fileoverview FROST Helper Utilities
 *
 * Provides common utility functions for key generation, nonce generation,
 * key tweaking, and public key format conversion.
 */

import { Buff, Bytes }     from '@vbyte/buff'
import { G, H }            from '@/ecc/index.js'
import { lift_x, mod_n }   from '@/ecc/util.js'
import { assert, hash340 } from '@/util/index.js'

/** BIP340 tagged hash domain for Schnorr signature challenges */
const BIP340_CHALLENGE_TAG = 'BIP0340/challenge'

/**
 * Generates a secret key using the FROST H3 hash function.
 *
 * @param aux - Optional 32-byte auxiliary input for deterministic generation
 * @returns A 32-byte secret key
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
 * Generates a secret nonce for use in FROST signing.
 *
 * Derives the nonce from the secret key and optional auxiliary randomness
 * using the FROST H3 hash function.
 *
 * @security CRITICAL: Each nonce MUST be used for exactly one signature.
 *           Nonce reuse enables extraction of the secret key. If aux_seed
 *           is provided for deterministic generation, ensure it is unique
 *           per signing session.
 *
 * @param secret - The secret key (typically the share's seckey)
 * @param aux_seed - Optional seed for deterministic nonce (default: random)
 * @returns A 32-byte secret nonce
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
 * Tweaks a secret key by scalar multiplication.
 *
 * @param seckey - The secret key to tweak
 * @param tweak - The tweak scalar
 * @returns The tweaked secret key (seckey * tweak mod N)
 */
export function tweak_seckey (
  seckey : Bytes,
  tweak  : Bytes
) : string {
  const coeff   = Buff.bytes(tweak).big
  const secret  = Buff.bytes(seckey).big
  const tweaked = mod_n(secret * coeff)
  return Buff.big(tweaked).hex
}

/**
 * Derives the public key from a secret key.
 *
 * Computes secret * G where G is the secp256k1 generator.
 *
 * @param secret - The secret key
 * @returns The public key as a 33-byte compressed point (hex)
 */
export function get_pubkey (secret : Bytes) {
  const scalar = Buff.bytes(secret).big
  const point  = G.ScalarBaseMulti(scalar)
  return G.SerializeElement(point).hex
}

/**
 * Tweaks a public key by scalar multiplication.
 *
 * Computes the point: tweak * P where P is the input public key point.
 * This is the public key corresponding to tweak_seckey(sk, tweak).
 *
 * @param pubkey - The public key to tweak (32 or 33 bytes)
 * @param tweak - The tweak scalar
 * @returns The tweaked public key (tweak * pubkey)
 */
export function tweak_pubkey (
  pubkey : Bytes,
  tweak  : Bytes
) : string {
  const coeff = Buff.bytes(tweak).big
  let   point = lift_x(pubkey)
        point = point.multiply(coeff)
  return G.SerializeElement(point).hex
}

/**
 * Computes the BIP340 Schnorr signature challenge.
 *
 * Computes e = H(R || P || m) using the BIP340/challenge tagged hash,
 * where R is the nonce point, P is the public key, and m is the message.
 *
 * @param pnonce - The group public nonce (R)
 * @param pubkey - The group public key (P)
 * @param message - The message being signed (m)
 * @returns The challenge as a bigint
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
  const digest = hash340(BIP340_CHALLENGE_TAG, grp_pn, grp_pk, message)
  return digest.big
}

/**
 * Converts a public key between ECDSA (33-byte) and BIP340 (32-byte) formats.
 *
 * @param pubkey - The public key to convert
 * @param type - Target format: 'ecdsa' for 33-byte, 'bip340' for 32-byte x-only
 * @returns The converted public key as a hex string
 * @throws Error if type is invalid
 */
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