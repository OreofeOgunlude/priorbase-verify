export type Tsa = {
    name: string;
    url: string;
};
export declare const TSAS: Tsa[];
export declare function caFile(): string;
export type TokenCheck = {
    ok: boolean;
    method: string;
    genTime: Date;
    detail?: string;
};
export declare function verifyToken(tokenDer: Buffer, hexDigest: string): TokenCheck;
export declare function stamp(hexDigest: string, tsa: Tsa): Promise<{
    token: Buffer;
    genTime: Date;
    method: string;
}>;
