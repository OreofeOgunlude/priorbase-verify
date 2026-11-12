import { type RecordEvent } from "./hash.ts";
import { type RecordAnchor, type RecordFile, type VerifyResult } from "./verify.ts";
export type RecordRest = Omit<RecordFile, "events">;
export declare class RecordScanner {
    private depth;
    private inString;
    private escape;
    private head;
    private str;
    private lastString;
    private pendingKey;
    private inEvents;
    private element;
    private onEvent;
    constructor(onEvent: (e: RecordEvent) => void);
    write(text: string): void;
    end(): RecordRest;
}
export declare function readRecord(chunks: AsyncIterable<string | Uint8Array>, onEvent: (e: RecordEvent) => void): Promise<RecordRest>;
export declare class ChainCheck {
    private chains;
    private problems;
    private events;
    private redacted;
    private wanted;
    constructor(opts?: {
        anchors?: {
            workspace_id: string;
            seq: number;
        }[];
    });
    feed(e: RecordEvent): void;
    hashAt(ws: string, seq: number): string | undefined;
    finish(rest: RecordRest, external?: RecordAnchor[], opts?: {
        skipAnchors?: boolean;
    }): VerifyResult;
}
