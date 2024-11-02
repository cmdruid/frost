import { CoreConfig, CoreDaemon } from '@cmdcode/core-cmd'
import { Test }       from 'tape'

import { frost_keygen, frost_sign } from '../lib/signer.js'

import { Address, Script, Signer, Tap, Tx } from '@cmdcode/tapscript'

export default async function (
  t      : Test,
  config : Partial<CoreConfig>
) {
  const core = new CoreDaemon(config)
  const client = await core.startup()

  t.test('Testing transaction signing', async t => {
    const group = frost_keygen()

    try {
      const pubkey = group.pubkey.slice(2)
      // Specify a basic script to use for testing.
      const script = [ pubkey, 'OP_CHECKSIG' ]
      const sbytes = Script.encode(script)
      // For tapscript spends, we need to convert this script into a 'tapleaf'.
      const tapleaf = Tap.tree.getLeaf(sbytes)
      // Generate a tapkey that includes our leaf script. Also, create a merlke proof 
      // (cblock) that targets our leaf and proves its inclusion in the tapkey.
      const [ tapkey, cblock ] = Tap.getPubKey(pubkey, { target: tapleaf })
      // Create a wallet to use as a faucet.
      const { faucet } = await client.load_wallets('faucet')
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
      const sighash   = Signer.taproot.hash(spend_template, 0, { extension: tapleaf })
      // Sign the hash using the frost quorum.
      const signature = frost_sign(group, sighash)
      // Add the signature to the witness.
      spend_template.vin[0].witness = [ signature, script, cblock ]
      // Publish the transaction.
      const spend_txid = await client.publish_tx(spend_template as any, true)
      t.pass('Tests completed with txid: ' + spend_txid)
    } catch (err) {
      console.log(err)
      t.fail('failed to create transaction')
    } finally {
      t.teardown(() => { core.shutdown() })
    }
  })
}
