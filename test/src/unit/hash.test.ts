import { Test } from 'tape'
import { Buff } from '@vbyte/buff'

import { H } from '@cmdcode/frost/ecc'

const { H1, H2, H3, H4, H5 } = H

export default function (tape: Test) {
  tape.test('Hash: H1-H5 produce consistent results', t => {
    const input = Buff.str('test input')

    // Each function should produce the same output for the same input
    const h1_a = H1(input)
    const h1_b = H1(input)
    t.equal(h1_a.hex, h1_b.hex, 'H1 is deterministic')

    const h2_a = H2(input)
    const h2_b = H2(input)
    t.equal(h2_a.hex, h2_b.hex, 'H2 is deterministic')

    const h3_a = H3(input)
    const h3_b = H3(input)
    t.equal(h3_a.hex, h3_b.hex, 'H3 is deterministic')

    const h4_a = H4(input)
    const h4_b = H4(input)
    t.equal(h4_a.hex, h4_b.hex, 'H4 is deterministic')

    const h5_a = H5(input)
    const h5_b = H5(input)
    t.equal(h5_a.hex, h5_b.hex, 'H5 is deterministic')

    t.end()
  })

  tape.test('Hash: Different inputs produce different outputs', t => {
    const input1 = Buff.str('input one')
    const input2 = Buff.str('input two')

    // H1
    t.notEqual(H1(input1).hex, H1(input2).hex, 'H1: different inputs -> different outputs')

    // H2
    t.notEqual(H2(input1).hex, H2(input2).hex, 'H2: different inputs -> different outputs')

    // H3
    t.notEqual(H3(input1).hex, H3(input2).hex, 'H3: different inputs -> different outputs')

    // H4
    t.notEqual(H4(input1).hex, H4(input2).hex, 'H4: different inputs -> different outputs')

    // H5
    t.notEqual(H5(input1).hex, H5(input2).hex, 'H5: different inputs -> different outputs')

    t.end()
  })

  tape.test('Hash: All functions output 32 bytes', t => {
    const input = Buff.str('test')

    t.equal(H1(input).length, 32, 'H1 outputs 32 bytes')
    t.equal(H2(input).length, 32, 'H2 outputs 32 bytes')
    t.equal(H3(input).length, 32, 'H3 outputs 32 bytes')
    t.equal(H4(input).length, 32, 'H4 outputs 32 bytes')
    t.equal(H5(input).length, 32, 'H5 outputs 32 bytes')

    t.end()
  })

  tape.test('Hash: Different functions produce different outputs for same input', t => {
    const input = Buff.str('same input for all')

    const h1 = H1(input).hex
    const h2 = H2(input).hex
    const h3 = H3(input).hex
    const h4 = H4(input).hex
    const h5 = H5(input).hex

    // Domain separation ensures different outputs
    t.notEqual(h1, h2, 'H1 != H2 (domain separation)')
    t.notEqual(h1, h3, 'H1 != H3 (domain separation)')
    t.notEqual(h1, h4, 'H1 != H4 (domain separation)')
    t.notEqual(h1, h5, 'H1 != H5 (domain separation)')
    t.notEqual(h2, h3, 'H2 != H3 (domain separation)')
    t.notEqual(h2, h4, 'H2 != H4 (domain separation)')
    t.notEqual(h2, h5, 'H2 != H5 (domain separation)')
    t.notEqual(h3, h4, 'H3 != H4 (domain separation)')
    t.notEqual(h3, h5, 'H3 != H5 (domain separation)')
    t.notEqual(h4, h5, 'H4 != H5 (domain separation)')

    t.end()
  })

  tape.test('Hash: Works with empty input', t => {
    const empty = new Uint8Array(0)

    // All functions should handle empty input without error
    t.ok(H1(empty).length === 32, 'H1 handles empty input')
    t.ok(H2(empty).length === 32, 'H2 handles empty input')
    t.ok(H3(empty).length === 32, 'H3 handles empty input')
    t.ok(H4(empty).length === 32, 'H4 handles empty input')
    t.ok(H5(empty).length === 32, 'H5 handles empty input')

    t.end()
  })

  tape.test('Hash: Works with large input', t => {
    const large = new Uint8Array(10000).fill(0x42)

    t.ok(H1(large).length === 32, 'H1 handles large input')
    t.ok(H2(large).length === 32, 'H2 handles large input')
    t.ok(H3(large).length === 32, 'H3 handles large input')
    t.ok(H4(large).length === 32, 'H4 handles large input')
    t.ok(H5(large).length === 32, 'H5 handles large input')

    t.end()
  })

  tape.test('Hash: H1-H3 outputs are valid scalars (less than curve order)', t => {
    // The curve order N for secp256k1
    const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')

    const input = Buff.random(32)

    // H1, H2, H3 use hash_to_field which should produce values < N
    const h1_val = H1(input).big
    const h2_val = H2(input).big
    const h3_val = H3(input).big

    t.ok(h1_val < N, 'H1 output is < curve order')
    t.ok(h2_val < N, 'H2 output is < curve order')
    t.ok(h3_val < N, 'H3 output is < curve order')

    t.end()
  })
}
