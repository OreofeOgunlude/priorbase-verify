import { type RecordRestV2, type Sealed } from "./chains.ts";
import type { RecordEvent } from "./hash.ts";
export declare const RECORD_FILE_FORMAT = "priorbase-record";
export type RecordAnchor = {
    workspace_id: string;
    seq: number;
    tsa: string;
    head_hash: string;
    token_base64: string;
};
export type RecordHead = {
    workspace_id: string;
    seq: number;
    hash: string;
};
export type RecordFile = {
    format: typeof RECORD_FILE_FORMAT;
    file_version: 1;
    exported_at: string;
    events: RecordEvent[];
    chain_heads: RecordHead[];
    anchors: RecordAnchor[];
};
export type RecordFileV2 = RecordRestV2 & {
    events: RecordEvent[];
};
export type AnyRecordFile = RecordFile | RecordFileV2;
export type VerifyResult = {
    problems: string[];
    chains: number;
    events: number;
    anchors: number;
    external: number;
    redacted: number;
    anchorsSkipped: boolean;
    earlier?: number;
    sealed?: Sealed[];
};
export declare function externalProblemsV2(rest: Pick<RecordRestV2, "anchors">, external: (RecordAnchor & {
    chain_id?: string | null;
})[]): string[];
export declare function verifyRecord(record: AnyRecordFile, external?: RecordAnchor[], opts?: {
    skipAnchors?: boolean;
}): VerifyResult;
