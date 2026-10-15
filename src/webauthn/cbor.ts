/** Bounded CBOR decoder for WebAuthn's definite-length attestation and COSE maps. */
export function decodeCBOR(bytes: Uint8Array, start = 0): { value: any, end: number } {
  let offset = start
  function read(depth: number): any {
    if (depth > 16 || offset >= bytes.length) throw new Error('Invalid CBOR')
    const head = bytes[offset++]!
    const major = head >> 5
    const additional = head & 31
    let size = additional
    if (additional >= 24) {
      const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : 0
      if (!width || offset + width > bytes.length) throw new Error('Invalid CBOR length')
      size = 0
      for (let i = 0; i < width; i++) size = size * 256 + bytes[offset++]!
    }
    if (major === 0) return size
    if (major === 1) return -1 - size
    if (major === 2 || major === 3) {
      if (size > bytes.length - offset) throw new Error('Truncated CBOR')
      const part = bytes.slice(offset, offset + size)
      offset += size
      return major === 2 ? part : new TextDecoder('utf-8', { fatal: true }).decode(part)
    }
    if (major === 4 || major === 5) {
      if (size > bytes.length - offset) throw new Error('Oversized CBOR')
      if (major === 4) return Array.from({ length: size }, () => read(depth + 1))
      const map = new Map<any, any>()
      for (let i = 0; i < size; i++) {
        const key = read(depth + 1)
        if (map.has(key)) throw new Error('Duplicate CBOR key')
        map.set(key, read(depth + 1))
      }
      return map
    }
    if (major === 7 && additional === 20) return false
    if (major === 7 && additional === 21) return true
    if (major === 7 && additional === 22) return null
    throw new Error('Unsupported CBOR')
  }
  return { value: read(0), end: offset }
}
