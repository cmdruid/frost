import { Test }               from 'tape'
import { combine_sig_shares } from '@/proto.js'
import { verify_sig }         from '@/sign.js'
import { get_full_context }   from '@/context.js'
import { SpecVector }         from '../types.js'

export default function (tape : Test, vector : SpecVector) {
  tape.test('Testing signature aggregation and verification', t => {

    const { grp_pubkey, message, sig } = vector.group
    
    const pnonces = vector.members.map(({ idx, pnonce_h, pnonce_b }) => {
      return { idx, pnonce_h, pnonce_b }
    })

    const context = get_full_context(grp_pubkey, pnonces, message)

    const sig_shares = vector.members.map(({ idx, psig }) => {
      return { idx, sig : psig }
    })

    const signature = combine_sig_shares(context, sig_shares)

    t.equals(signature, sig, 'aggregate signature should match vector')

    const is_valid = verify_sig(context, message, signature)

    t.true(is_valid, 'signature should be a valid schnorr signature')

    t.end()

  })
}
