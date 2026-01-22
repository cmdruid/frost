/**
 * @fileoverview FROST Secret Share Type Definitions
 *
 * Types for representing secret and public shares in the FROST protocol.
 * Shares are evaluated points on a polynomial and can be combined via
 * Lagrange interpolation to reconstruct the secret.
 */

/**
 * A secret share package with an owner index.
 *
 * Extends SecretShareSet with the index of the participant who created
 * this package. Used in DKG and refresh protocols.
 */
export type SecretSharePackage = SecretShareSet & {
  /** The index of the participant who created this package */
  idx : number
}

/**
 * A participant's secret share in the threshold scheme.
 *
 * Contains the share index (1-indexed, never 0) and the secret key
 * value which is a point on the polynomial evaluated at that index.
 *
 * @security WARNING: The `seckey` field is a secret value. Serializing,
 *           logging, or transmitting this object exposes the secret key.
 *           Never store shares in plaintext or include them in error messages.
 *           See SECURITY.md for details.
 *
 * @property idx - The participant's 1-based index (share number)
 * @property seckey - The secret key as a 32-byte hex string
 */
export interface SecretShare {
  /** The participant's 1-based index (share number) */
  idx    : number
  /** The secret key as a 32-byte hex string */
  seckey : string
}

/**
 * A public share containing a participant's index and public key.
 *
 * Used in ECDH and other operations where public key contributions
 * need to be associated with specific participants.
 *
 * @property idx - The participant's 1-based index
 * @property pubkey - The public key as a 33-byte compressed hex string
 */
export interface PublicShare {
  /** The participant's 1-based index */
  idx    : number
  /** The public key as a 33-byte compressed hex string */
  pubkey : string
}

/**
 * A set of secret shares with VSS commitments for verification.
 *
 * Created during key generation (dealer mode or DKG). The VSS commitments
 * allow recipients to verify their shares without learning the secret.
 *
 * @property shares - Array of secret shares for each participant
 * @property vss_commits - Array of VSS commitments (public keys for polynomial coefficients)
 */
export interface SecretShareSet {
  /** Array of secret shares for each participant */
  shares      : SecretShare[]
  /** Array of VSS commitments (coefficient public keys) */
  vss_commits : string[]
}

/**
 * A complete dealer share set including the group public key.
 *
 * Extends SecretShareSet with the group public key, which is the
 * first VSS commitment (corresponding to the constant coefficient,
 * i.e., the shared secret).
 *
 * @property group_pk - The group public key (33-byte compressed hex)
 */
export interface DealerShareSet extends SecretShareSet {
  /** The group public key (first VSS commitment) */
  group_pk : string
}
