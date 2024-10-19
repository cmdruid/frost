import tape         from 'tape'
import shares_test  from './src/shares.js'
import commit_test  from './src/commit.js'
import context_test from './src/context.js'
import dkg_test     from './src/dkg.js'
import signer_test  from './src/sign.js'
import combine_test from './src/aggregate.js'
import stress_test  from './src/stress.js'
import tx_test      from './src/tx.js'

import vector from './src/vectors/spec.json' assert { type : 'json' }

tape('Bifrost Test Suite', async t => {
  
  shares_test(t,  vector)
  dkg_test(t)
  commit_test(t,  vector)
  context_test(t, vector)
  signer_test(t,  vector)
  combine_test(t, vector)
  
  await tx_test(t)

  stress_test(t, 10, 100)

})
