import { Buff, Bytes }   from '@cmdcode/buff'
import { G }             from '@/ecc/index.js'
import { _0n, _1n }      from '@/const.js'
import { assert }        from '@/util/index.js'
import { mod_n, lift_x } from '@/ecc/util.js'

/**
 * Creates a list of coefficients for use
 * in a Shamir Secret Sharing scheme.
 * 
 * For a deterministic result, you must provide the
 * same number of secrets as the threshold value.
 *  
 * @param secrets   : An array of 32-byte values.
 * @param threshold : The number of coefficients to generate.
 * @returns         : A list of bigints.
 */
export function create_share_coeffs (
  secrets   : Bytes[],
  threshold : number,
) {
  const coeffs : bigint[] = []
  for (let i = 0; i < threshold; i++) {
    const secret = secrets.at(i)
    const coeff  = (secret !== undefined)
      ? Buff.bytes(secret).big
      : Buff.random(32).big
    coeffs.push(mod_n(coeff))
  }
  return coeffs
}

/**
 * Create a list of public key commitments, one for each coefficient.
 */
export function get_share_commits (
  share_coeffs : Bytes[]
) : string[] {
  // For each coefficient in the list:
  return share_coeffs.map(e => {
    // Convert to a scalar value.
    const scalar = Buff.bytes(e).big
    // Return the generator point value, in hex.
    return G.ScalarBaseMulti(scalar).toHex(true)
  })
}

/**
 * Create a list of public key commitments, one for each coefficient.
 */
export function merge_share_commits (
  commits_a : string[],
  commits_b : string[]
) : string[] {
  assert.equal_arr_size(commits_a, commits_b)
  // Define an array of updated commits.
  const commits : string[] = []
  // For each commit in the list:
  for (let i = 0; i < commits_a.length; i++) {
    const point_a = lift_x(commits_a[i])
    const point_b = lift_x(commits_b[i])
    const point_c = G.ElementAdd(point_a, point_b)
    const commit  = G.SerializeElement(point_c)
    commits.push(commit.hex)
  }
  // Return the updated commits.
  return commits
}
