import tape           from 'tape'

import shares_test     from './src/unit/shares.test.js'
import commit_test     from './src/unit/commit.test.js'
import context_test    from './src/unit/context.test.js'
import dkg_test        from './src/unit/dkg.test.js'
import signer_test     from './src/unit/sign.test.js'
import combine_test    from './src/unit/aggregate.test.js'
import ecdh_test       from './src/unit/ecdh.test.js'
import recover_test    from './src/unit/recover.test.js'
import refresh_test    from './src/unit/refresh.test.js'
import hash_test       from './src/unit/hash.test.js'
import poly_test       from './src/unit/poly.test.js'
import errors_test     from './src/unit/errors.test.js'
import security_test   from './src/unit/security.test.js'
import helpers_test    from './src/unit/helpers.test.js'
import edge_cases_test from './src/unit/edge-cases.test.js'
import stress_test     from './src/e2e/stress.test.js'
import tweak_test      from './src/e2e/tweak.test.js'

import vector from './src/vectors/spec.json' with { type : 'json' }

tape('Frost Test Suite', async t => {

  shares_test(t,  vector)
  dkg_test(t)
  commit_test(t,  vector)
  context_test(t, vector)
  signer_test(t,  vector)
  combine_test(t, vector)
  tweak_test(t)

  // New unit tests
  ecdh_test(t)
  recover_test(t)
  refresh_test(t)
  hash_test(t)
  poly_test(t)
  errors_test(t)
  security_test(t)
  helpers_test(t)
  edge_cases_test(t)

  stress_test(t, 10, 100)
})
