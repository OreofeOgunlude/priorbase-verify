// Verifies a whole record: every chain recomputes, every chain head matches,
// every anchor still points at its entry and every timestamp token is genuine.
// Works on the downloadable JSON record, so it runs offline. Reads both
// shapes: file version 1 (one chain per workspace) and file version 2
// (record 2.0: one chain per study, sealed into the workspace's chain).

import { ChainsCheck, type RecordRestV2, type Sealed } from "./chains.ts";
import type { RecordEvent } from "./hash.ts";
import { ChainCheck } from "./stream.ts";

export const RECORD_FILE_FORMAT = "priorbase-record";

export type RecordAnchor = { workspace_id: string; seq: number; tsa: string; head_hash: string; token_base64: string };
export type RecordHead = { workspace_id: string; seq: number; hash: string };

export type RecordFile = {
  format: typeof RECORD_FILE_FORMAT;
  file_version: 1;
  exported_at: string;
  events: RecordEvent[];
  chain_heads: RecordHead[];
  anchors: RecordAnchor[];
};

// record 2.0: a study's file, or a workspace's
export type RecordFileV2 = RecordRestV2 & { events: RecordEvent[] };
export type AnyRecordFile = RecordFile | RecordFileV2;

export type VerifyResult = {
  problems: string[];
  chains: number;
  events: number;
  anchors: number;
  external: number;
  // entries of other studies given as hashes only (a study's export)
  redacted: number;
  // anchor tokens not checked (--skip-anchors)
  anchorsSkipped: boolean;
  // file version 2: entries written before the rechain, and how far each study chain is sealed
  earlier?: number;
  sealed?: Sealed[];
};

// Copies kept outside the database (record 2.0): each the same token the
// record holds, for the same entry.
export function externalProblemsV2(
  rest: Pick<RecordRestV2, "anchors">,
  external: (RecordAnchor & { chain_id?: string | null })[],
): string[] {
  const problems: string[] = [];
  for (const x of external) {
    const chain = x.chain_id ?? null;
    const inRecord = rest.anchors.find(
      (a) => a.workspace_id === x.workspace_id && a.chain_id === chain && a.seq === x.seq && a.tsa === x.tsa,
    );
    const where = chain ?? x.workspace_id;
    if (!inRecord) problems.push(`${where}: external anchor ${x.seq}-${x.tsa} is missing from the record`);
    else if (inRecord.token_base64 !== x.token_base64)
      problems.push(`${where}: external anchor ${x.seq}-${x.tsa} differs from the record's copy`);
    else if (inRecord.head_hash !== x.head_hash)
      problems.push(`${where}: external anchor ${x.seq}-${x.tsa} names another hash`);
  }
  return problems;
}

export function verifyRecord(
  record: AnyRecordFile,
  external: RecordAnchor[] = [],
  opts: { skipAnchors?: boolean } = {},
): VerifyResult {
  if (record.format === RECORD_FILE_FORMAT && record.file_version === 2) {
    const check = new ChainsCheck();
    // each chain in order of seq; entries written before the rechain first
    const key = (e: RecordEvent) => (e.format_version === 3 ? `1:${e.chain_id}` : `0:${e.workspace_id}`);
    const ordered = [...record.events].sort((a, b) => (key(a) === key(b) ? a.seq - b.seq : key(a) < key(b) ? -1 : 1));
    for (const e of ordered) check.feed(e);
    const { events: _events, ...rest } = record;
    void _events;
    const r = check.finish(rest, opts);
    r.problems.push(...externalProblemsV2(rest, external));
    return { ...r, external: external.length };
  }
  if (record.format !== RECORD_FILE_FORMAT || record.file_version !== 1) {
    return {
      problems: [`not a ${RECORD_FILE_FORMAT} file version 1`],
      chains: 0,
      events: 0,
      anchors: 0,
      external: 0,
      redacted: 0,
      anchorsSkipped: !!opts.skipAnchors,
    };
  }
  // the same check the streaming reader runs (stream.ts), each chain in order of seq
  const check = new ChainCheck();
  const ordered = [...record.events].sort((a, b) =>
    a.workspace_id === b.workspace_id ? a.seq - b.seq : a.workspace_id < b.workspace_id ? -1 : 1,
  );
  for (const e of ordered) check.feed(e);
  const { events: _events, ...rest } = record;
  void _events;
  return check.finish(rest, external, opts);
}
