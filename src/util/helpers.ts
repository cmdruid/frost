import { Buff } from '@cmdcode/buff'

export function random_bytes (size = 32) {
  return Buff.random(size)
}

export function count_scalars (x_j : bigint, L : bigint[]) {
  return L.filter(x => x === x_j).length
}

export function get_record <T extends { idx : number }> (
  records : T[],
  idx     : number
) {
  const record = records.find(e => e.idx === idx)
  if (record === undefined) {
    throw new Error('record not found for index: ' + idx)
  }
  return record
}