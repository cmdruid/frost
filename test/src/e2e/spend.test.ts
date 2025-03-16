import { CoreClient } from '@cmdcode/core-cmd'
import { Test }       from 'tape'

import { frost_keygen, frost_sign } from '../lib/signer.js'
import { Address, Signer, Tap, Tx } from '@cmdcode/tapscript'

export default async function (
  t      : Test,
  client : CoreClient,
) {

  t.test('Testing taproot key spending', async t => {
    const group  = frost_keygen()

    try {
      // Get the group pubkey formatted for taproot .
      const pubkey = group.group_pk.slice(2)
      const taptwk = Tap.tweak.getTweak(pubkey).hex
      // Create a tapkey from the group pubkey and tweak.
      const tapkey = Tap.tweak.tweakPubKey(pubkey, taptwk).slice(1).hex
      // Create a wallet to use as a faucet.
      const faucet = await client.load_wallet('faucet')
      // Ensure the wallet has funds to spend.
      await faucet.ensure_funds(1_000_000)
      // Generate a return address from the faucet.
      const return_addr = await faucet.new_address
      // Create a tx template that pays to the group pubkey.
      const recv_template = {
        vout : [{
          value : 100_000,
          scriptPubKey : [ 'OP_1', tapkey ]
        }]
      }
      // Fund the tx using the faucet's wallet.
      const txdata = await faucet.fund_tx(recv_template)
      // Publish the tx and mine a block.
      const txid = await client.publish_tx(txdata, true)
      // Create a tx template that spends from the group pubkey.
      const spend_template = Tx.create({
        vin : [{
          txid,
          vout    : 0,
          prevout : recv_template.vout[0]
        }],
        vout : [{
          value        : 99_000,
          scriptPubKey : Address.toScriptPubKey(return_addr)
        }]
      })
      // Create the transaction hash.
      const sighash   = Signer.taproot.hash(spend_template, 0)
      // Sign the hash using the frost quorum.
      const signature = frost_sign(group, sighash, [ taptwk ])
      // Add the signature to the witness.
      spend_template.vin[0].witness = [ signature ]
      // Publish the transaction.
      const spend_txid = await client.publish_tx(spend_template as any, true)
      t.pass('Tests completed with txid: ' + spend_txid)
    } catch (err) {
      console.log(err)
      t.fail('failed to create transaction')
    }
  })
}
