import { Buff }   from '@cmdcode/buff'
import { assert } from '@/util/index.js'

import type {
  CommitPackage,
  GroupPackage,
  SecretPackage
} from '@/types/index.js'

export function encode_group_pkg (
  pkg : GroupPackage
) : string {
  const thd  = Buff.num(pkg.threshold, 4)
  const gpk  = Buff.hex(pkg.group_pk,  33)
  const com  = pkg.commits.map(e => serialize_commit_pkg(e))
  const data = Buff.join([ gpk, thd, ...com ])
  assert.size(data, 37 + (com.length * 103))
  return data.to_bech32m('bfgroup')
}

export function decode_group_pkg (
  str : string
) : GroupPackage {
  const stream    = Buff.bech32m(str).stream
  const group_pk  = stream.read(33).hex
  const threshold = stream.read(4).num
  assert.ok(stream.size % 103 === 0, 'commit data is malformed')
  const count   = stream.size / 103
  const commits : CommitPackage[] = []
  for (let i = 0; i < count; i++) {
    const cbytes = stream.read(103)
    commits.push(deserialize_commit_pkg(cbytes))
  }
  assert.size(stream.data, 0)
  return { commits, group_pk, threshold }
}

export function encode_secret_pkg (
  pkg : SecretPackage
) : string {
  const idx  = Buff.num(pkg.idx, 4)
  const ssk  = Buff.hex(pkg.share_sk,  32)
  const bsn  = Buff.hex(pkg.binder_sn, 32)
  const hsn  = Buff.hex(pkg.hidden_sn, 32)
  const data = Buff.join([ idx, ssk, bsn, hsn ])
  assert.size(data, 100)
  return data.to_bech32m('bfshare')
}

export function decode_secret_pkg (
  str : string
) : SecretPackage {
  const stream = Buff.bech32m(str).stream
  assert.size(stream.data, 100)
  const idx       = stream.read(4).num
  const share_sk  = stream.read(32).hex
  const binder_sn = stream.read(32).hex
  const hidden_sn = stream.read(32).hex
  assert.size(stream.data, 0)
  return { idx, binder_sn, hidden_sn, share_sk }
}

function serialize_commit_pkg (
  pkg : CommitPackage
) : Uint8Array {
  const idx = Buff.num(pkg.idx, 4)
  const spk = Buff.hex(pkg.share_pk,  33)
  const bpn = Buff.hex(pkg.binder_pn, 33)
  const hpn = Buff.hex(pkg.hidden_pn, 33)
  return Buff.join([ idx, spk, bpn, hpn ])
}

function deserialize_commit_pkg (
  data : Uint8Array
) : CommitPackage {
  const stream    = new Buff(data).stream
  assert.size(stream.data, 103)
  const idx       = stream.read(4).num
  const share_pk  = stream.read(33).hex
  const binder_pn = stream.read(33).hex
  const hidden_pn = stream.read(33).hex
  assert.size(stream.data, 0)
  return { idx, binder_pn, hidden_pn, share_pk }
}
