import { type RecordEvent } from "./hash.ts";
export type ChainHeadV2 = {
    chain_id: string | null;
    workspace_id: string;
    study_id: string | null;
    seq: number;
    hash: string;
};
export type AnchorV2 = {
    workspace_id: string;
    chain_id: string | null;
    seq: number;
    tsa: string;
    head_hash: string;
    token_base64: string;
};
export type Scope = {
    kind: "study";
    workspace_id: string;
    study_id: string;
} | {
    kind: "workspace";
    workspace_id: string;
} | {
    kind: "own";
    workspace_id: string;
};
export type RecordRestV2 = {
    format: "priorbase-record";
    file_version: 2;
    exported_at: string;
    scope: Scope;
    chains: ChainHeadV2[];
    anchors: AnchorV2[];
};
export type Sealed = {
    chain_id: string;
    seq: number;
    head: number;
    by: number | null;
    anchored: number | null;
};
export type VerifyResultV2 = {
    problems: string[];
    chains: number;
    events: number;
    anchors: number;
    redacted: number;
    earlier: number;
    sealed: Sealed[];
    anchorsSkipped: boolean;
};
export declare class SealsAhead {
    readonly seals: Map<string, number>;
    feed(e: RecordEvent): void;
}
export declare const leafOf: (chainId: string, seq: number, hash: string) => string;
export declare class ChainsCheck {
    private chains;
    private legacy;
    private seals;
    private problems;
    private events;
    private redacted;
    private ahead;
    private wanted;
    constructor(opts?: {
        seals?: Map<string, number>;
        anchors?: AnchorV2[];
    });
    private keeps;
    feed(e: RecordEvent): void;
    private feedLegacy;
    hashAt(chainId: string, seq: number): string | undefined;
    sealOf(chainId: string, anchors: AnchorV2[], from?: number): Sealed | null;
    finish(rest: RecordRestV2, opts?: {
        skipAnchors?: boolean;
    }): VerifyResultV2;
}
export declare function anchoredAfterV2(record: {
    events: RecordEvent[];
    anchors: AnchorV2[];
}, e: Pick<RecordEvent, "format_version" | "chain_id" | "study_id" | "workspace_id" | "seq">): number | null;
