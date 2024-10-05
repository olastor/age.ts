import { bech32 } from "@scure/base"
import { hmac } from "@noble/hashes/hmac"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { randomBytes } from "@noble/hashes/utils"
import * as x25519 from "./x25519.js"
import { scryptUnwrap, scryptWrap, x25519Identity, x25519Unwrap, x25519Wrap } from "./recipients.js"
import { encodeHeader, encodeHeaderNoMAC, parseHeader, Stanza } from "./format.js"
import { decryptSTREAM, encryptSTREAM } from "./stream.js"

export function generateIdentity(): Promise<string> {
  const scalar = randomBytes(32)
  const identity = bech32.encode("AGE-SECRET-KEY-", bech32.toWords(scalar), false).toUpperCase()
  return Promise.resolve(identity)
}

export async function identityToRecipient(identity: string | CryptoKey): Promise<string> {
  let scalar: Uint8Array | CryptoKey
  if (isCryptoKey(identity)) {
    scalar = identity
  } else {
    const res = bech32.decodeToBytes(identity)
    if (!identity.startsWith("AGE-SECRET-KEY-1") ||
      res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
      res.bytes.length !== 32)
      throw Error("invalid identity")
    scalar = res.bytes
  }

  const recipient = await x25519.scalarMultBase(scalar)
  return bech32.encode("age", bech32.toWords(recipient), false)
}

export interface Plugin<Recipient, Identity> {
  name: string
  handleRecipient: (recipientBytes: Uint8Array) => Recipient
  handleIdentityAsRecipient: (identityBytes: Uint8Array) => Recipient
  handleIdentity: (identityBytes: Uint8Array) => Identity
  wrapFileKey: (recipient: Recipient, fileKey: Uint8Array) => Stanza | Promise<Stanza>
  unwrapFileKey: (identity: Identity, stanzas: Stanza[]) => Uint8Array | Promise<Uint8Array | null> | null
}

export { Stanza, x25519Wrap, x25519Unwrap }

export class Encrypter {
  private passphrase: string | null = null
  private scryptWorkFactor = 18
  private recipients: Uint8Array[] = []

  private pluginRecipients: Record<string, any[]> = {}
  private plugins: Record<string, Plugin<any, any>> = {}

  registerPlugin(plugin: Plugin<any, any>): void {
    this.plugins[plugin.name] = plugin
  }

  setPassphrase(s: string): void {
    if (this.passphrase !== null)
      throw new Error("can encrypt to at most one passphrase")
    if (this.recipients.length !== 0)
      throw new Error("can't encrypt to both recipients and passphrases")
    this.passphrase = s
  }

  setScryptWorkFactor(logN: number): void {
    this.scryptWorkFactor = logN
  }

  addIdentity(s: string): void {
    // TODO: validation
    const res = bech32.decodeToBytes(s.toLowerCase())
    const pluginName = res.prefix.replace(/^age-plugin-/, '')
    if (!this.plugins[pluginName])
      throw Error(`No plugin handler present for identity of type ${pluginName}`)

    if (!this.pluginRecipients[pluginName]) this.pluginRecipients[pluginName] = []
    this.pluginRecipients[pluginName].push(this.plugins[pluginName].handleIdentityAsRecipient(res.bytes))
  }

  addRecipient(s: string): void {
    if (this.passphrase !== null)
      throw new Error("can't encrypt to both recipients and passphrases")
    const res = bech32.decodeToBytes(s)

    if (!s.startsWith("age1") ||
      !res.prefix.toLowerCase().startsWith("age") ||
      (res.prefix.toLowerCase() === 'age' && res.bytes.length !== 32))
      throw Error("invalid recipient")

    if (res.prefix === 'age') {
      this.recipients.push(res.bytes)
      return
    }

    const pluginName = res.prefix.replace(/^age1/, '')
    if (!this.plugins[pluginName])
      throw Error(`No plugin handler present for recipient of type ${pluginName}`)

    if (!this.pluginRecipients[pluginName]) this.pluginRecipients[pluginName] = []
    this.pluginRecipients[pluginName].push(this.plugins[pluginName].handleRecipient(res.bytes))
  }

  async encrypt(file: Uint8Array | string): Promise<Uint8Array> {
    if (typeof file === "string") {
      file = new TextEncoder().encode(file)
    }

    const fileKey = randomBytes(16)
    const stanzas: Stanza[] = []

    for (const data of this.recipients) {
      stanzas.push(await x25519Wrap(fileKey, data))
    }
    if (this.passphrase !== null) {
      stanzas.push(scryptWrap(fileKey, this.passphrase, this.scryptWorkFactor))
    }

    for (const [name, recs] of Object.entries(this.pluginRecipients)) {
      for (const r of recs) {
        stanzas.push(await this.plugins[name].wrapFileKey(r, fileKey))
      }
    }

    const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32)
    const mac = hmac(sha256, hmacKey, encodeHeaderNoMAC(stanzas))
    const header = encodeHeader(stanzas, mac)

    const nonce = randomBytes(16)
    const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32)
    const payload = encryptSTREAM(streamKey, file)

    const out = new Uint8Array(header.length + nonce.length + payload.length)
    out.set(header)
    out.set(nonce, header.length)
    out.set(payload, header.length + nonce.length)
    return out
  }
}

export class Decrypter {
  private passphrases: string[] = []
  private identities: x25519Identity[] = []
  private pluginIdentities: Record<string, any[]> = {}
  private plugins: Record<string, Plugin<any,any>> = {}

  registerPlugin(name: string, plugin: Plugin<any,any>): void {
    this.plugins[name] = plugin
  }

  addPassphrase(s: string): void {
    this.passphrases.push(s)
  }

  addIdentity(s: string | CryptoKey): void {
    if (isCryptoKey(s)) {
      this.identities.push({
        identity: s,
        recipient: x25519.scalarMultBase(s),
      })
      return
    }
    const res = bech32.decodeToBytes(s)

    if (res.prefix.startsWith("age-plugin-")) {
      const pluginName = res.prefix.toLowerCase().replace("age-plugin-", "").slice(0, -1)
      if (!this.pluginIdentities[pluginName]) this.pluginIdentities[pluginName] = []
      this.pluginIdentities[pluginName].push(this.plugins[pluginName].handleIdentity(res.bytes))
      return
    }

    if (!s.startsWith("AGE-SECRET-KEY-1") ||
      res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
      res.bytes.length !== 32)
      throw Error("invalid identity")

    this.identities.push({
      identity: res.bytes,
      recipient: x25519.scalarMultBase(res.bytes),
    })
  }

  async decrypt(file: Uint8Array, outputFormat?: "uint8array"): Promise<Uint8Array>
  async decrypt(file: Uint8Array, outputFormat: "text"): Promise<string>
  async decrypt(file: Uint8Array, outputFormat?: "text" | "uint8array"): Promise<string | Uint8Array> {
    const h = parseHeader(file)
    const fileKey = await this.unwrapFileKey(h.recipients)
    if (fileKey === null) {
      throw Error("no identity matched any of the file's recipients")
    }

    const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32)
    const mac = hmac(sha256, hmacKey, h.headerNoMAC)
    if (!compareBytes(h.MAC, mac)) {
      throw Error("invalid header HMAC")
    }

    const nonce = h.rest.subarray(0, 16)
    const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32)
    const payload = h.rest.subarray(16)

    const out = decryptSTREAM(streamKey, payload)
    if (outputFormat === "text") return new TextDecoder().decode(out)
    return out
  }

  private async unwrapFileKey(recipients: Stanza[]): Promise<Uint8Array | null> {
    for (const s of recipients) {
      // Ideally this should be implemented by passing all stanzas to the scrypt
      // identity implementation, and letting it throw the error. In practice,
      // this is a very simple implementation with no public identity interface.
      if (s.args.length > 0 && s.args[0] === "scrypt" && recipients.length !== 1) {
        throw Error("scrypt recipient is not the only one in the header")
      }

      for (const p of this.passphrases) {
        const k = scryptUnwrap(s, p)
        if (k !== null) { return k }
      }

      for (const i of this.identities) {
        const k = await x25519Unwrap(s, i)
        if (k !== null) { return k }
      }
    }

    for (const [name, ids] of Object.entries(this.pluginIdentities)) {
      for (const i of ids) {
        const k = await this.plugins[name].unwrapFileKey(i, recipients)
        if (k !== null) return k
      }
    }

    return null
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) { return false }
  let acc = 0
  for (let i = 0; i < a.length; i++) {
    acc |= a[i] ^ b[i]
  }
  return acc === 0
}

function isCryptoKey(key: unknown): key is CryptoKey {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey
}
