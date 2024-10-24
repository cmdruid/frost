import type {
  GroupPackage,
  SecretPackage
} from '@/types/index.js'

export function encode_group_pkg (
  pkg : GroupPackage
) {
  // Unpack object.
  // Serialize into bytes.
  // Return as bech32 encoded string.
}

export function decode_group_pkg (
  encoded : string
) : GroupPackage {
  // Decode into bytes.
  // Parse back into parts.
  // Return as package object
}

export function encode_secret_pkg (
  pkg : SecretPackage
) {

}

export function decode_secret_pkg (
  encoded : string
) : SecretPackage {

}
