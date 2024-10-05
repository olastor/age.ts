import { x25519Unwrap, x25519Wrap } from "./recipients.js";
import { Stanza } from "./format.js";
export declare function generateIdentity(): Promise<string>;
export declare function identityToRecipient(identity: string | CryptoKey): Promise<string>;
export interface PluginRecipient {
    wrapFileKey: (fileKey: Uint8Array) => Stanza | Promise<Stanza>;
}
export interface PluginIdentity {
    unwrapFileKey: (stanzas: Stanza[]) => Uint8Array | Promise<Uint8Array | null> | null;
}
export type handleRecipientType = (recipientBytes: Uint8Array) => PluginRecipient;
export type handleIdentityAsRecipientType = (identityBytes: Uint8Array) => PluginRecipient;
export type handleIdentityType = (identityBytes: Uint8Array) => PluginIdentity;
export interface Plugin {
    name: string;
    handleRecipient: handleRecipientType;
    handleIdentityAsRecipient: handleIdentityAsRecipientType;
    handleIdentity: handleIdentityType;
}
export { Stanza, x25519Wrap, x25519Unwrap };
export declare class Encrypter {
    private passphrase;
    private scryptWorkFactor;
    private recipients;
    private pluginRecipients;
    private plugins;
    registerPlugin(plugin: Plugin): void;
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
    registerPlugin(name: string, plugin: Plugin): void;
    addPassphrase(s: string): void;
    addIdentity(s: string | CryptoKey): void;
    decrypt(file: Uint8Array, outputFormat?: "uint8array"): Promise<Uint8Array>;
    decrypt(file: Uint8Array, outputFormat: "text"): Promise<string>;
    private unwrapFileKey;
}
