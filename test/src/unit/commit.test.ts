import { Test }       from 'tape'
import { SpecVector } from '../types.js'

import { create_commit_pkg } from '@bifrost/lib'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing nonce commitments', t => {

    for (const mbr of vector.members) {
      const { idx, seckey, nseed_h, nseed_b } = mbr

      const pkg = create_commit_pkg({ idx, seckey }, nseed_h, nseed_b)

      const { secnonce, pubnonce } = pkg
      
      t.equal(secnonce.hidden_sn, mbr.snonce_h, `[${idx}] hidden nonce should match vector`)
      t.equal(secnonce.binder_sn, mbr.snonce_b, `[${idx}] binder nonce should match vector`)
      t.equal(pubnonce.hidden_pn, mbr.pnonce_h, `[${idx}] hidden commit should match vector`)
      t.equal(pubnonce.binder_pn, mbr.pnonce_b, `[${idx}] binder commit should match vector`)
    }

    t.end()

  })
}
