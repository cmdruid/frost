/**
 * @fileoverview FROST Domain-Separated Hash Functions (H1-H5)
 *
 * Implements the domain-separated hash functions as specified in
 * draft-irtf-cfrg-frost-15, section 6.5 (FROST(secp256k1, SHA-256)).
 *
 * @see https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-frostsecp256k1-sha-256
 *
 * Domain separation ensures that hash outputs for different purposes
 * cannot collide, which is critical for the security of the FROST protocol.
 * Each function uses a unique Domain Separation Tag (DST) suffix.
 */

import { Buff }             from '@vbyte/buff'
import { sha256 }           from '@noble/hashes/sha2.js'
import { DOMAIN, DST, _N }  from '@/const.js'
import { str_to_bytes }     from './util.js'

import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js'

/** Hash-to-field options for secp256k1 with SHA-256 */
const OPT = { m: 1, p: _N, k: 128, expand: 'xmd', hash: sha256 } as const

/**
 * Creates hash-to-field options with a specific Domain Separation Tag.
 * @param DST - The domain separation tag string
 * @returns Options object for hash_to_field
 */
function get_opts (DST : string) {
  return { ...OPT, DST }
}

/**
 * H1: Hash function for computing binding factors (rho).
 *
 * Used in Round 2 to bind each participant's commitment to the group
 * commitment and message, preventing rogue-key attacks.
 *
 * DST: "FROST-secp256k1-SHA256-v1rho"
 *
 * @param msg - The input message (typically encoded commitment list || message)
 * @returns A 32-byte scalar in the curve order
 */
export function H1 (msg : Uint8Array) {
  const tag  = DOMAIN + DST.RHO
  const nums = hash_to_field(msg, 1, get_opts(tag))
  return Buff.big(nums[0][0], 32)
}

/**
 * H2: Hash function for computing the Schnorr challenge.
 *
 * Computes the challenge value 'c' in the Schnorr signature scheme.
 * Input is typically (group_commitment || group_pubkey || message).
 *
 * DST: "FROST-secp256k1-SHA256-v1chal"
 *
 * @param msg - The input message (R || P || m in Schnorr notation)
 * @returns A 32-byte scalar in the curve order
 */
export function H2 (msg : Uint8Array) {
  const tag  = DOMAIN + DST.CHAL
  const nums = hash_to_field(msg, 1, get_opts(tag))
  return Buff.big(nums[0][0], 32)
}

/**
 * H3: Hash function for deriving secret nonces.
 *
 * Used for deterministic nonce generation from a seed, secret share,
 * and optional auxiliary randomness. Critical for preventing nonce reuse.
 *
 * DST: "FROST-secp256k1-SHA256-v1nonce"
 *
 * @security Nonce reuse leads to private key extraction. Always use
 *           fresh randomness or ensure deterministic inputs are unique.
 *
 * @param msg - The input message (typically random || secret || aux_data)
 * @returns A 32-byte scalar in the curve order
 */
export function H3 (msg : Uint8Array) {
  const tag  = DOMAIN + DST.NONCE
  const nums = hash_to_field(msg, 1, get_opts(tag))
  return Buff.big(nums[0][0], 32)
}

/**
 * H4: Hash function for pre-hashing the message.
 *
 * Pre-hashes the message before signing to ensure consistent
 * message handling regardless of message length.
 *
 * DST: "FROST-secp256k1-SHA256-v1msg"
 *
 * @param msg - The raw message to be signed
 * @returns A 32-byte hash of the message
 */
export function H4 (msg : Uint8Array) {
  const tag  = str_to_bytes(DOMAIN + DST.MSG)
  const hash = sha256(new Uint8Array([ ...tag, ...msg ]))
  return new Buff(hash)
}

/**
 * H5: Hash function for commitment encoding.
 *
 * Hashes the serialized commitment list for use in binding factor
 * computation. Ensures commitment binding is consistent.
 *
 * DST: "FROST-secp256k1-SHA256-v1com"
 *
 * @param msg - The serialized commitment list
 * @returns A 32-byte hash of the commitments
 */
export function H5 (msg : Uint8Array) {
  const tag  = str_to_bytes(DOMAIN + DST.COM)
  const hash = sha256(new Uint8Array([ ...tag, ...msg ]))
  return new Buff(hash)
}
