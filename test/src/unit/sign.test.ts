import { Test }       from 'tape'
import { SpecVector } from '../types.js'

import {
  get_pubkey,
  get_session_ctx,
  sign_msg,
  verify_partial_sig
} from '@bifrost/lib'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing signature share creation and verification', t => {

    const { grp_pubkey, message } = vector.group

    const pnonces = vector.members.map(({ idx, pnonce_h, pnonce_b }) => {
      return { idx, binder_pn: pnonce_b, hidden_pn : pnonce_h }
    })

    const context = get_session_ctx(grp_pubkey, pnonces, message)

    for (const mbr of vector.members) {
      const { idx, seckey, snonce_h, snonce_b, pnonce_h, pnonce_b } = mbr
      const secshare  = { idx, seckey }
      const secnonce  = { idx, hidden_sn: snonce_h, binder_sn: snonce_b }
      const pubnonce  = { idx, hidden_pn: pnonce_h, binder_pn: pnonce_b }
      const sig_share = sign_msg(context, secshare, secnonce)
      
      t.equal(sig_share.psig, mbr.psig, `[${idx}] signature share should match vector`)

      const pubkey    = get_pubkey(seckey)
      const is_valid  = verify_partial_sig(context, pubnonce, pubkey, sig_share.psig)
      
      t.true(is_valid, `[${idx}] signature share should pass validation`)
    }

    t.end()

  })
}
