import { Test }       from 'tape'
import { SpecVector } from '../types.js'

import {
  combine_partial_sigs,
  get_pubkey,
  get_session_ctx,
  verify_final_sig
} from '@cmdcode/frost/lib'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing signature aggregation and verification', t => {

    const { grp_pubkey, message, sig } = vector.group
    
    const pnonces = vector.members.map(({ idx, pnonce_h, pnonce_b }) => {
      return { idx, hidden_pn: pnonce_h, binder_pn: pnonce_b }
    })

    const context = get_session_ctx(grp_pubkey, pnonces, message)

    const sig_shares = vector.members.map(({ idx, psig, seckey }) => {
      const pubkey = get_pubkey(seckey)
      return { idx, psig, pubkey }
    })

    const signature = combine_partial_sigs(context, sig_shares)

    t.equals(signature, sig, 'aggregate signature should match vector')

    const is_valid = verify_final_sig(context, message, signature)

    t.true(is_valid, 'signature should be a valid schnorr signature')

    t.end()

  })
}
