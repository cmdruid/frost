import { Test }             from 'tape'
import { SpecVector }       from './types.js'
import { get_pubkey }       from '@/util.js'
import { get_full_context } from '@/context.js'

import {
  sign_msg,
  verify_sig_share
} from '@/sign.js'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing signature share creation and verification', t => {

    const { grp_pubkey, message } = vector.group

    const pnonces = vector.members.map(({ idx, pnonce_h, pnonce_b }) => {
      return { idx, pnonce_h, pnonce_b }
    })

    const context = get_full_context(grp_pubkey, pnonces, message)

    for (const mbr of vector.members) {
      const { idx, seckey, snonce_h, snonce_b, pnonce_h, pnonce_b } = mbr
      const secshare  = { idx, seckey }
      const secnonce  = { idx, snonce_h, snonce_b }
      const pubnonce  = { idx, pnonce_h, pnonce_b }
      const sig_share = sign_msg(context, secshare, secnonce)
      
      t.equal(sig_share.sig, mbr.psig, `[${idx}] signature share should match vector`)

      const pubkey    = get_pubkey(seckey)
      const is_valid  = verify_sig_share(context, pubnonce, pubkey, sig_share.sig)
      
      t.true(is_valid, `[${idx}] signature share should pass validation`)
    }

    t.end()

  })
}
