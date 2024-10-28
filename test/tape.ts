import tape         from 'tape'
import shares_test  from './src/unit/shares.test.js'
import commit_test  from './src/unit/commit.test.js'
import context_test from './src/unit/context.test.js'
import dkg_test     from './src/unit/dkg.test.js'
import signer_test  from './src/unit/sign.test.js'
import combine_test from './src/unit/aggregate.test.js'
import stress_test  from './src/e2e/stress.test.js'
import tx_test      from './src/e2e/tx.test.js'

import vector from './src/vectors/spec.json' assert { type : 'json' }

tape('Frost Test Suite', async t => {
  
  shares_test(t,  vector)
  dkg_test(t)
  commit_test(t,  vector)
  context_test(t, vector)
  signer_test(t,  vector)
  combine_test(t, vector)
  
  await tx_test(t)

  stress_test(t, 10, 100)
})
