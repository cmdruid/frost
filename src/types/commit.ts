/**
 * @fileoverview FROST Commitment Type Definitions
 *
 * Types for nonce commitments used in Round 1 of FROST signing.
 * Each participant generates two nonces (hiding and binding) and
 * commits to them before learning the message.
 */

/**
 * A complete commitment package containing both secret and public nonces.
 *
 * Created by `create_commit_pkg()` during Round 1. The secret nonces
 * are kept private and used in Round 2; the public nonces are broadcast.
 *
 * @note This intersection type merges SecretNonce and PublicNonce. The `idx`
 *       property appears in both types with the same meaning (participant index).
 */
export type CommitmentPackage = SecretNonce & PublicNonce

/**
 * Secret nonces for a signing session.
 *
 * Contains the two secret nonce values that are used in Round 2 to
 * create a partial signature. These MUST be kept confidential.
 *
 * @security CRITICAL: Each nonce pair MUST be used for exactly one signature.
 *           Nonce reuse enables extraction of the secret share.
 *           WARNING: Serializing, logging, or transmitting this object exposes
 *           the secret nonces. Never store nonces persistently or share them
 *           with other parties. See SECURITY.md for details.
 *
 * @property idx - The participant's 1-based index
 * @property binder_sn - The binding secret nonce (32-byte hex)
 * @property hidden_sn - The hiding secret nonce (32-byte hex)
 */
export interface SecretNonce {
  /** The participant's 1-based index */
  idx       : number
  /** The binding secret nonce (32-byte hex) */
  binder_sn : string
  /** The hiding secret nonce (32-byte hex) */
  hidden_sn : string
}

/**
 * Public nonce commitments for a signing session.
 *
 * Contains the public points corresponding to the secret nonces.
 * These are broadcast to all participants in Round 1.
 *
 * @property idx - The participant's 1-based index
 * @property binder_pn - The binding public nonce (33-byte compressed hex)
 * @property hidden_pn - The hiding public nonce (33-byte compressed hex)
 */
export interface PublicNonce {
  /** The participant's 1-based index */
  idx       : number
  /** The binding public nonce (33-byte compressed hex) */
  binder_pn : string,
  /** The hiding public nonce (33-byte compressed hex) */
  hidden_pn : string
}

/**
 * A binding factor for a participant in a signing session.
 *
 * Binding factors ensure each participant's nonce contribution is
 * uniquely bound to the group commitment and message, preventing
 * related-nonce attacks.
 *
 * @property idx - The participant's 1-based index
 * @property factor - The binding factor value (32-byte hex)
 */
export interface BindFactor {
  /** The participant's 1-based index */
  idx    : number
  /** The binding factor value (32-byte hex) */
  factor : string
}
