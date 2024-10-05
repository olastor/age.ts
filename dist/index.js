var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { bech32 } from "@scure/base";
import { hmac } from "@noble/hashes/hmac";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import * as x25519 from "./x25519.js";
import { scryptUnwrap, scryptWrap, x25519Unwrap, x25519Wrap } from "./recipients.js";
import { encodeHeader, encodeHeaderNoMAC, parseHeader, Stanza } from "./format.js";
import { decryptSTREAM, encryptSTREAM } from "./stream.js";
export function generateIdentity() {
    const scalar = randomBytes(32);
    const identity = bech32.encode("AGE-SECRET-KEY-", bech32.toWords(scalar), false).toUpperCase();
    return Promise.resolve(identity);
}
export function identityToRecipient(identity) {
    return __awaiter(this, void 0, void 0, function* () {
        let scalar;
        if (isCryptoKey(identity)) {
            scalar = identity;
        }
        else {
            const res = bech32.decodeToBytes(identity);
            if (!identity.startsWith("AGE-SECRET-KEY-1") ||
                res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
                res.bytes.length !== 32)
                throw Error("invalid identity");
            scalar = res.bytes;
        }
        const recipient = yield x25519.scalarMultBase(scalar);
        return bech32.encode("age", bech32.toWords(recipient), false);
    });
}
export { Stanza, x25519Wrap, x25519Unwrap };
export class Encrypter {
    constructor() {
        this.passphrase = null;
        this.scryptWorkFactor = 18;
        this.recipients = [];
        this.plugins = {};
    }
    registerPlugin(name, handler) {
        this.plugins[name] = handler;
    }
    setPassphrase(s) {
        if (this.passphrase !== null)
            throw new Error("can encrypt to at most one passphrase");
        if (this.recipients.length !== 0)
            throw new Error("can't encrypt to both recipients and passphrases");
        this.passphrase = s;
    }
    setScryptWorkFactor(logN) {
        this.scryptWorkFactor = logN;
    }
    addRecipient(s) {
        if (this.passphrase !== null)
            throw new Error("can't encrypt to both recipients and passphrases");
        const res = bech32.decodeToBytes(s);
        if (!s.startsWith("age1") ||
            !res.prefix.toLowerCase().startsWith("age") ||
            (res.prefix.toLowerCase() === 'age' && res.bytes.length !== 32))
            throw Error("invalid recipient");
        if (res.prefix === 'age') {
            this.recipients.push({
                type: res.prefix,
                data: res.bytes
            });
            return;
        }
        const pluginName = res.prefix.replace(/^age1/, '');
        if (!this.plugins[pluginName])
            throw Error(`No plugin handler present for recipient of type ${pluginName}`);
        this.recipients.push({
            type: pluginName,
            data: res.bytes
        });
    }
    encrypt(file) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof file === "string") {
                file = new TextEncoder().encode(file);
            }
            const fileKey = randomBytes(16);
            const stanzas = [];
            for (const { type, data } of this.recipients) {
                if (type === 'age') {
                    stanzas.push(yield x25519Wrap(fileKey, data));
                }
                else {
                    stanzas.push(yield this.plugins[type](fileKey, data));
                }
            }
            if (this.passphrase !== null) {
                stanzas.push(scryptWrap(fileKey, this.passphrase, this.scryptWorkFactor));
            }
            const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32);
            const mac = hmac(sha256, hmacKey, encodeHeaderNoMAC(stanzas));
            const header = encodeHeader(stanzas, mac);
            const nonce = randomBytes(16);
            const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32);
            const payload = encryptSTREAM(streamKey, file);
            const out = new Uint8Array(header.length + nonce.length + payload.length);
            out.set(header);
            out.set(nonce, header.length);
            out.set(payload, header.length + nonce.length);
            return out;
        });
    }
}
export class Decrypter {
    constructor() {
        this.passphrases = [];
        this.identities = [];
        this.pluginIdentities = {};
        this.plugins = {};
    }
    registerPlugin(name, handler) {
        this.plugins[name] = handler;
    }
    addPassphrase(s) {
        this.passphrases.push(s);
    }
    addIdentity(s) {
        if (isCryptoKey(s)) {
            this.identities.push({
                identity: s,
                recipient: x25519.scalarMultBase(s),
            });
            return;
        }
        const res = bech32.decodeToBytes(s);
        if (res.prefix.startsWith("age-plugin-")) {
            const pluginName = res.prefix.replace("age-plugin-", "").toLowerCase().slice(0, -1);
            if (!this.pluginIdentities[pluginName]) {
                this.pluginIdentities[pluginName] = [];
            }
            this.pluginIdentities[pluginName].push(res.bytes);
            return;
        }
        if (!s.startsWith("AGE-SECRET-KEY-1") ||
            res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" ||
            res.bytes.length !== 32)
            throw Error("invalid identity");
        this.identities.push({
            identity: res.bytes,
            recipient: x25519.scalarMultBase(res.bytes),
        });
    }
    decrypt(file, outputFormat) {
        return __awaiter(this, void 0, void 0, function* () {
            const h = parseHeader(file);
            const fileKey = yield this.unwrapFileKey(h.recipients);
            if (fileKey === null) {
                throw Error("no identity matched any of the file's recipients");
            }
            const hmacKey = hkdf(sha256, fileKey, undefined, "header", 32);
            const mac = hmac(sha256, hmacKey, h.headerNoMAC);
            if (!compareBytes(h.MAC, mac)) {
                throw Error("invalid header HMAC");
            }
            const nonce = h.rest.subarray(0, 16);
            const streamKey = hkdf(sha256, fileKey, nonce, "payload", 32);
            const payload = h.rest.subarray(16);
            const out = decryptSTREAM(streamKey, payload);
            if (outputFormat === "text")
                return new TextDecoder().decode(out);
            return out;
        });
    }
    unwrapFileKey(recipients) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            for (const s of recipients) {
                // Ideally this should be implemented by passing all stanzas to the scrypt
                // identity implementation, and letting it throw the error. In practice,
                // this is a very simple implementation with no public identity interface.
                if (s.args.length > 0 && s.args[0] === "scrypt" && recipients.length !== 1) {
                    throw Error("scrypt recipient is not the only one in the header");
                }
                for (const p of this.passphrases) {
                    const k = scryptUnwrap(s, p);
                    if (k !== null) {
                        return k;
                    }
                }
                for (const i of this.identities) {
                    const k = yield x25519Unwrap(s, i);
                    if (k !== null) {
                        return k;
                    }
                }
                if (((_a = this.pluginIdentities[s.args[0]]) === null || _a === void 0 ? void 0 : _a.length) && this.plugins[s.args[0]]) {
                    for (const i of this.pluginIdentities[s.args[0]]) {
                        const k = yield this.plugins[s.args[0]](s, i);
                        if (k !== null) {
                            return k;
                        }
                    }
                }
            }
            return null;
        });
    }
}
function compareBytes(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    let acc = 0;
    for (let i = 0; i < a.length; i++) {
        acc |= a[i] ^ b[i];
    }
    return acc === 0;
}
function isCryptoKey(key) {
    return typeof CryptoKey !== "undefined" && key instanceof CryptoKey;
}
