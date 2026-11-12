// Writing the record file as it is read from the database (Phase 7c): one
// entry per line, each written as it comes, so the export never holds the
// whole file. Type imports only: the download route uses this without
// pulling in the verifier's checks.

import type { AnchorV2, ChainHeadV2, Scope } from "./chains.ts";
import type { RecordEvent } from "./hash.ts";
import type { RecordAnchor, RecordHead } from "./verify.ts";

// The record file as text, one entry per line, written as the entries come:
// the export streams it, and nothing ever holds the whole file.
export async function* recordJson(
  exportedAt: string,
  events: AsyncIterable<RecordEvent>,
  tail: () => Promise<{ chain_heads: RecordHead[]; anchors: RecordAnchor[] }>,
): AsyncGenerator<string> {
  yield `{"format":"priorbase-record","file_version":1,"exported_at":${JSON.stringify(exportedAt)},"events":[`;
  let first = true;
  for await (const e of events) {
    yield `${first ? "" : ","}\n${JSON.stringify(e)}`;
    first = false;
  }
  const t = await tail();
  yield `\n],"chain_heads":${JSON.stringify(t.chain_heads)},"anchors":${JSON.stringify(t.anchors)}}\n`;
}

// Record 2.0, file version 2: the same, with the file's scope and each chain's head.
export async function* recordJsonV2(
  exportedAt: string,
  scope: Scope,
  events: AsyncIterable<RecordEvent>,
  tail: () => Promise<{ chains: ChainHeadV2[]; anchors: AnchorV2[] }>,
): AsyncGenerator<string> {
  yield `{"format":"priorbase-record","file_version":2,"exported_at":${JSON.stringify(exportedAt)},"scope":${JSON.stringify(scope)},"events":[`;
  let first = true;
  for await (const e of events) {
    yield `${first ? "" : ","}\n${JSON.stringify(e)}`;
    first = false;
  }
  const t = await tail();
  yield `\n],"chains":${JSON.stringify(t.chains)},"anchors":${JSON.stringify(t.anchors)}}\n`;
}
