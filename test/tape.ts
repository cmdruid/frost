import tape           from 'tape'
import { CoreConfig } from '@cmdcode/core-cmd'

import shares_test  from './src/unit/shares.test.js'
import commit_test  from './src/unit/commit.test.js'
import context_test from './src/unit/context.test.js'
import dkg_test     from './src/unit/dkg.test.js'
import signer_test  from './src/unit/sign.test.js'
import combine_test from './src/unit/aggregate.test.js'
import stress_test  from './src/e2e/stress.test.js'
import tx_test      from './src/e2e/tx.test.js'

import vector from './src/vectors/spec.json' assert { type : 'json' }

/* You may need to modify this config depending on your setup. */

const config : Partial<CoreConfig> = {
  corepath : 'test/bin/bitcoind',
  clipath  : 'test/bin/bitcoin-cli',
  confpath : 'test/bitcoin.conf',
  datapath : 'test/data',
  verbose  : false,
  debug    : false,
  isolated : true,
  network  : 'regtest'
}

tape('Frost Test Suite', async t => {
  
  shares_test(t,  vector)
  dkg_test(t)
  commit_test(t,  vector)
  context_test(t, vector)
  signer_test(t,  vector)
  combine_test(t, vector)
  
  await tx_test(t, config)

  stress_test(t, 10, 100)
})
