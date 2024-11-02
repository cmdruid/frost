/* needs to be refactored, coming soon! */

// import { random_bytes } from '@cmdcode/frost/util'

// import {
//   combine_partial_sigs,
//   create_commit_pkg,
//   create_key_group,
//   get_commit_pkg,
//   get_pubkey,
//   get_session_ctx,
//   sign_msg,
//   verify_final_sig,
//   verify_partial_sig,
//   verify_share
// } from '@cmdcode/frost/lib'

// const seckey  = random_bytes(32).hex
// const message = random_bytes(32).hex
// const pubkey  = get_pubkey(seckey)

// console.log('master pk:', pubkey)

// const secrets = [ seckey ]

// const share_ct = 3
// const thold    = 2

// // Generate a secret, package of shares, and group key.
// const a_group = create_key_group(thold, share_ct, secrets)

// console.log('a_group pk:', a_group.pubkey)

// // Use a t amount of shares to create nonce commitments.
// const a_shares  = a_group.shares.slice(0, thold)
// const a_commits = a_shares.map(e => create_commit_pkg(e))

// // Compute some context data for the signing session.
// const a_ctx = get_session_ctx(a_group.pubkey, a_commits, message)
// const a_idx = a_ctx.indexes.map(e => Number(e) - 1)

// // Create the partial signatures for a given signing context.
// const a_psigs = a_idx.map(i => {
//   const share  = a_shares[i]
//   const commit = get_commit_pkg(a_commits, share)
//   const sig = sign_msg(a_ctx, share, commit)
//   if (!verify_partial_sig(a_ctx, commit, sig.pubkey, sig.psig)) {
//     throw new Error('sig share failed validation')
//   }
//   return sig
// })

// // Aggregate the partial signatures into a single signature.
// const a_signature = combine_partial_sigs(a_ctx, a_psigs)
// const a_is_valid  = verify_final_sig(a_ctx, message, a_signature)

// console.log('Group A is valid:', a_is_valid)
// console.log('group A shares:', a_group.shares)

// // Update shares.
// const c_group = refresh_share_group(a_group)

// console.log('c_group pk:', c_group.pubkey)

// // Verify that all shares are included in the group key.
// c_group.shares.every(e => {
//   if (!verify_share(c_group.commits, e, thold)) {
//     throw new Error('invalid share in the group at index: ' + e.idx)
//   }
// })

// // Use a t amount of shares to create nonce commitments.
// const c_shares  = c_group.shares.slice(0, thold)
// const c_commits = c_shares.map(e => create_commit_pkg(e))

// // Compute some context data for the signing session.
// const c_ctx = get_session_ctx(c_group.pubkey, c_commits, message)
// const c_idx = c_ctx.indexes.map(e => Number(e) - 1)

// // Create the partial signatures for a given signing context.
// const c_psigs = c_idx.map(i => {
//   const share  = c_shares[i]
//   const commit = get_commit_pkg(c_commits, share)
//   const sig = sign_msg(c_ctx, share, commit)
//   if (!verify_partial_sig(c_ctx, commit, sig.pubkey, sig.psig)) {
//     throw new Error('sig share failed validation')
//   }
//   return sig
// })

// // Aggregate the partial signatures into a single signature.
// const c_signature = combine_partial_sigs(c_ctx, c_psigs)
// const c_is_valid  = verify_final_sig(c_ctx, message, c_signature)

// console.log('Group C is valid:', c_is_valid)
// console.log('group C shares:', c_group.shares)
