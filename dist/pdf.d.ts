export declare const MANIFEST_FORMAT = "priorbase-manifest";
export type Manifest = {
    format: typeof MANIFEST_FORMAT;
    version: 1;
    workspace_id: string;
    study_id: string;
    study: string;
    revision_id: string;
    rev: number;
    fingerprint: string;
    fingerprint_version: number;
    body_sha256: string;
    signed: {
        name: string;
        credential: string | null;
        at: string;
        method: string;
    };
    approvals: {
        name: string;
        credential: string | null;
        at: string;
        method: string;
        final?: boolean;
    }[];
    errata: {
        at: string;
        text: string;
        reason: string;
    }[];
};
export type PdfRead = {
    manifest: Manifest | null;
    bodySha256: string | null;
    pages: number;
    problem: string | null;
};
export declare function readPdf(bytes: Uint8Array): PdfRead;
