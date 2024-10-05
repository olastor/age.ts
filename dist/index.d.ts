import { x25519Unwrap, x25519Wrap } from "./recipients.js";
import { Stanza } from "./format.js";
export declare function generateIdentity(): Promise<string>;
export declare function identityToRecipient(identity: string | CryptoKey): Promise<string>;
export type PluginRecipientV1 = (fileKey: Uint8Array, recipients: string[], identities: string[]) => Promise<Stanza[]>;
export type PluginIdentityV1 = (stanza: Stanza, identity: string) => Promise<Uint8Array | null>;
export { Stanza, x25519Wrap, x25519Unwrap };
export declare class Encrypter {
    private passphrase;
    private scryptWorkFactor;
    private recipients;
    private pluginRecipients;
    private pluginIdentities;
    private plugins;
    registerPlugin(name: string, handler: PluginRecipientV1): void;
    setPassphrase(s: string): void;
    setScryptWorkFactor(logN: number): void;
    addIdentity(s: string): void;
    addRecipient(s: string): void;
    encrypt(file: Uint8Array | string): Promise<Uint8Array>;
}
export declare class Decrypter {
    private passphrases;
    private identities;
    private pluginIdentities;
    private plugins;
    registerPlugin(name: string, handler: PluginIdentityV1): void;
    addPassphrase(s: string): void;
    addIdentity(s: string | CryptoKey): void;
    decrypt(file: Uint8Array, outputFormat?: "uint8array"): Promise<Uint8Array>;
    decrypt(file: Uint8Array, outputFormat: "text"): Promise<string>;
    private unwrapFileKey;
}
