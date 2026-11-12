import type { AnchorV2, ChainHeadV2, Scope } from "./chains.ts";
import type { RecordEvent } from "./hash.ts";
import type { RecordAnchor, RecordHead } from "./verify.ts";
export declare function recordJson(exportedAt: string, events: AsyncIterable<RecordEvent>, tail: () => Promise<{
    chain_heads: RecordHead[];
    anchors: RecordAnchor[];
}>): AsyncGenerator<string>;
export declare function recordJsonV2(exportedAt: string, scope: Scope, events: AsyncIterable<RecordEvent>, tail: () => Promise<{
    chains: ChainHeadV2[];
    anchors: AnchorV2[];
}>): AsyncGenerator<string>;
