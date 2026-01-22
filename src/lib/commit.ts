/**
 * @fileoverview FROST Commitment Operations
 *
 * Implements Round 1 of the FROST protocol where participants generate
 * nonce commitments for a signing session. Also provides utilities for
 * computing binding factors and group nonces.
 *
 * @see https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html
 */

import { Buff, Bytes }        from '@vbyte/buff'
import { H, G }               from '@/ecc/index.js'
import { _0n, _1n }           from '@/const.js'
import { assert, get_record } from '@/util/index.js'

import {
  generate_nonce,
  get_pubkey
} from './helpers.js'

import type {
  CurveElement,
  CommitmentPackage,
  SecretShare,
  PublicNonce,
  BindFactor
} from '@/types/index.js'

/**
 * Extracts participant indices from a list of public nonces.
 *
 * @param pnonces - Array of public nonce commitments
 * @returns Array of participant indices as bigints
 */
export function get_nonce_ids (
  pnonces : PublicNonce[]
) : bigint[] {
  return pnonces.map(pn => BigInt(pn.idx))
}

/**
 * Encodes and concatenates all public nonce commitments for hashing.
 *
 * Sorts commitments by participant index and serializes them into a
 * single byte string. Used as input to the commitment hash function.
 *
 * Format: (idx_1 || D_1 || E_1 || ... || idx_n || D_n || E_n)
 * where D is the hiding nonce and E is the binding nonce.
 *
 * @param pnonces - Array of public nonce commitments
 * @returns Concatenated encoded commitments as a Buff
 */
export function get_commits_prefix (
  pnonces : PublicNonce[]
) {
  const enc_group_commit: Bytes[] = []
  const sorted_pnonces = pnonces.sort((a, b) => a.idx - b.idx)
  for (const { idx, hidden_pn, binder_pn } of sorted_pnonces) {
    const enc_commit = [ G.SerializeScalar(idx), hidden_pn, binder_pn ]
    enc_group_commit.push(...enc_commit)
  }
  return Buff.join(enc_group_commit)
}

/**
 * Constructs a byte-prefix for the signing session.
 *
 * Combines the group public key, hashed message, and hashed commitment list
 * into a single prefix used for computing binding factors.
 *
 * @param pnonces - Array of public nonce commitments from all participants
 * @param group_pk - The group public key (33-byte compressed hex)
 * @param message - The message being signed (hex-encoded)
 * @returns Concatenated prefix: (group_pk || H4(message) || H5(commits))
 */
export function get_group_prefix (
  pnonces  : PublicNonce[],
  group_pk : string,
  message  : string
) : Buff {
  const msg_bytes   = Buff.hex(message)
  const msg_hash    = H.H4(msg_bytes)
  const commit_list = get_commits_prefix(pnonces)
  const commit_hash = H.H5(commit_list)
  return Buff.join([ group_pk, msg_hash, commit_hash ])
}

/**
 * Retrieves the binding factor for a specific participant.
 *
 * Binding factors ensure that each participant's nonce is uniquely bound
 * to the group commitment and message, preventing related-nonce attacks.
 *
 * @param binders - Array of pre-computed binding factors
 * @param idx - The participant index to look up
 * @returns The binding factor as a bigint
 * @throws Error if the participant index is not found
 */
export function get_bind_factor (
  binders : BindFactor[],
  idx     : number
) : bigint {
  for (const bind of binders) {
    if (idx === bind.idx) {
      return Buff.bytes(bind.factor).big
    }
  }
  throw new Error('invalid participant')
}

/**
 * Computes binding factors for all participants in a signing session.
 *
 * Each binding factor rho_i = H1(prefix || i) ensures that participant i's
 * nonce contribution is uniquely bound to the session context.
 *
 * @param nonces - Array of public nonce commitments
 * @param prefix - The session prefix (group_pk || H4(msg) || H5(commits))
 * @returns Array of binding factors for each participant
 */
export function get_group_binders (
  nonces : PublicNonce[],
  prefix : Bytes
) : BindFactor[] {
  return nonces.map(({ idx }) => {
    const scalar    = G.SerializeScalar(idx)
    const rho_input = Buff.join([ prefix, scalar ])
    return { idx, factor: H.H1(rho_input).hex }
  })
}

/**
 * Computes the aggregated group public nonce (R) for the signing session.
 *
 * Combines all participants' public nonces using their binding factors:
 * R = sum(D_i + rho_i * E_i) for all participants i
 *
 * The resulting R value becomes the r component of the Schnorr signature.
 *
 * @param pnonces - Array of public nonce commitments
 * @param binders - Array of binding factors for each participant
 * @returns The group public nonce as a 33-byte compressed point (hex)
 */
export function get_group_pubnonce (
  pnonces : PublicNonce[],
  binders : BindFactor[]
) : string {
  let group_commit : CurveElement | null = null

  for (const { idx, binder_pn, hidden_pn } of pnonces) {
    const hidden_elem   = G.DeserializeElement(hidden_pn)
    const binding_elem  = G.DeserializeElement(binder_pn)
    const bind_factor   = get_bind_factor(binders, idx)
    const factored_elem = G.ScalarMulti(binding_elem, bind_factor)
    group_commit = G.ElementAdd(group_commit, hidden_elem)
    group_commit = G.ElementAdd(group_commit, factored_elem)
  }
  assert.exists(group_commit)
  return G.SerializeElement(group_commit).hex
}

/**
 * Creates a commitment package for Round 1 of a FROST signing session.
 *
 * Generates two nonces (hiding and binding) and their corresponding public
 * commitments. The secret nonces are used in Round 2 for signing.
 *
 * @security The secret nonces (hidden_sn, binder_sn) MUST be kept confidential
 *           and used exactly once. Nonce reuse enables private key extraction.
 *           If seeds are provided, they must be unique per signing session.
 *
 * @param secret_share - The participant's secret share
 * @param hidden_seed - Optional seed for deterministic hiding nonce (default: random)
 * @param binder_seed - Optional seed for deterministic binding nonce (default: random)
 * @returns A commitment package containing both secret and public nonces
 */
export function create_commit_pkg (
  secret_share : SecretShare,
  hidden_seed ?: string,
  binder_seed ?: string
) : CommitmentPackage {
  const { idx, seckey } = secret_share
  const binder_sn = generate_nonce(seckey, binder_seed).hex
  const hidden_sn = generate_nonce(seckey, hidden_seed).hex
  const binder_pn = get_pubkey(binder_sn)
  const hidden_pn = get_pubkey(hidden_sn)
  return { idx, binder_pn, binder_sn, hidden_pn, hidden_sn }
}

/**
 * Retrieves a participant's commitment package by share index.
 *
 * @param commits - Array of commitment packages from all participants
 * @param share - The secret share to look up
 * @returns The matching commitment package
 * @throws Error if no commitment exists for the share index
 */
export function get_commit_pkg (
  commits : CommitmentPackage[],
  share   : SecretShare
) : CommitmentPackage {
  const idx    = share.idx
  return get_record(commits, idx)
}
