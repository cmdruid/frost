/**
 * TODO:
 * 
 * We need to create a trusted dealer that generates a set of key packages.
 * 
 * We also need to define what a key package is, and how to encode/decode it.
 * 
 * We need to define a method for creating a nonce tweak.
 * Remember the nonce tweak should not interfere with the FROST protocol.
 * The nonces will get tweaked going in, and the binder prefixes can be computed as normal.
 * 
 * We need to be able to tweak a root nonce with a nonce tweak.
 * 
 * We need to define a partial signature method, that accepts a private key and root nonce, and returns a partial signature.
 * 
 * We need a method to verify a partial signature (and check it is in our group), then co-sign and aggregate.
 * 
 * KEY PACKAGE SCHEMA:
 * - share_idx
 * - share_sk
 * - root_sn
 * - threshold
 * - list of (share_idx, share_pn, root_pn)(with dealer as idx_0)
 * 
 * generate_shares()
 * rotate_shares(packages)
 * 
 * encode_package(pkg)
 * decode_package(pkgstr)
 * verify_package(pkg)
 * 
 * compute_root_tweak()
 * get_tweaked_nonce()
 * 
 * sign_msg ()
 * verify_psig()
 * combine_psigs()
 * 
 */

export function generate_share_pkgs () {

  // Generate shares.

  // Generate root nonces.

  

}