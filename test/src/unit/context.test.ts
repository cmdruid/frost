import { Buff }       from '@cmdcode/buff'
import { Test }       from 'tape'
import { SpecVector } from '../types.js'
import { get_record } from '@cmdcode/frost/util'

import {
  get_commit_binders,
  get_commit_prefix,
  get_group_nonce,
  get_challenge
} from '@cmdcode/frost/lib'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing signature context', t => {

    const { challenge, grp_pnonce, grp_pubkey, grp_prefix, message }  = vector.group

    const pnonces = vector.members.map(({ idx, pnonce_h, pnonce_b }) => {
      return { idx, hidden_pn: pnonce_h, binder_pn: pnonce_b }
    })

    const prefix  = get_commit_prefix(pnonces, grp_pubkey, message).hex
    const binders = get_commit_binders(pnonces, prefix)

    t.equal(prefix, grp_prefix, 'binder prefix should match vector')

    for (const mbr of vector.members) {
      const binder = get_record(binders, mbr.idx)
      t.equal(binder.key, mbr.binder, `[${mbr.idx}] binder factor should match vector`)
    }

    const group_nonce = get_group_nonce(pnonces, binders)
    
    t.equal(group_nonce, grp_pnonce, 'group pubnonce should match vector')

    const group_chall = get_challenge(group_nonce, grp_pubkey, message)

    t.equal(Buff.big(group_chall, 32).hex, challenge, 'group challenge should match vector')

    t.end()

  })
}
