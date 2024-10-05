export declare function forceWebCryptoOff(off: boolean): void;
export declare const isX25519Supported: () => Promise<boolean>;
export declare function scalarMult(scalar: Uint8Array | CryptoKey, u: Uint8Array): Promise<Uint8Array>;
export declare function scalarMultBase(scalar: Uint8Array | CryptoKey): Promise<Uint8Array>;
