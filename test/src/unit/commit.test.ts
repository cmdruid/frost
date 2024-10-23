import { Test }       from 'tape'
import { SpecVector } from '../types.js'

import { create_nonce_pkg } from '@bifrost/lib'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing nonce commitments', t => {

    for (const mbr of vector.members) {
      const { idx, seckey, nseed_h, nseed_b } = mbr

      const pkg = create_nonce_pkg({ idx, seckey }, nseed_h, nseed_b)

      const { sec_nonces, pub_nonces } = pkg
      
      t.equal(sec_nonces.snonce_h, mbr.snonce_h, `[${idx}] hidden nonce should match vector`)
      t.equal(sec_nonces.snonce_b, mbr.snonce_b, `[${idx}] binder nonce should match vector`)
      t.equal(pub_nonces.pnonce_h, mbr.pnonce_h, `[${idx}] hidden commit should match vector`)
      t.equal(pub_nonces.pnonce_b, mbr.pnonce_b, `[${idx}] binder commit should match vector`)
    }

    t.end()

  })
}
