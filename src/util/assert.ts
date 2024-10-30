import { Buff, Bytes } from '@cmdcode/buff'

export function ok (value : unknown, message ?: string) : asserts value {
  if (value === false) throw new Error(message ?? 'Assertion failed!')
}

export function exists <T> (
  input ?: T | null
) : asserts input is NonNullable<T> {
  if (typeof input === 'undefined') {
    throw new TypeError('Input is undefined!')
  }
  if (input === null) {
    throw new TypeError('Input is null!')
  }
}

export function size (
  input : Bytes,
  size  : number
) : boolean {
  const bytes = Buff.bytes(input)
  if (bytes.length !== size) {
    throw new Error(`Invalid byte size: ${bytes.hex} !== ${size}`)
  }
  return true
}

export function is_included <T> (
  array : T[],
  item  : T
) {
  if (!array.includes(item)) {
    throw new Error('item is not included in array')
  }
}

export function is_unique_set <T> (array : T[]) {
  for (const x of array) {
    const c = array.filter(e => e === x).length
    if (c !== 1) {
      throw new Error('item in set is not unique: ' + String(x))
    }
  }
}

export function is_equal_set <T> (array : T[]) {
  if (!array.every(e => e === array[0])) {
    throw new Error('set does not have equal items')
  }
}

export function equal_arr_size <T> (
  array_a : T[],
  array_b : T[]
) {
  if (array_a.length !== array_b. length) {
    throw new Error(`array lengths are unequal: ${array_a.length} !== ${array_b.length}`)
  }
}
