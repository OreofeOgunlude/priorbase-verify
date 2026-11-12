// The record's hash chain, computed independently of the database. If this code
// and the database's audit.compute_row_hash ever disagree, verification fails.
//
// Canonical form: for each field in order, <byte length>:<value>; a missing
// value is written as -1:. hash = sha256(prev_hash || utf8(canonical)). The
// first entry of each chain has 32 zero bytes as prev_hash.
//
// Formats 1 and 2: one chain per workspace (seq is the workspace's). Format 3
// (record 2.0): one chain per study, and one for the workspace's own entries
// (chain_id is the study or the workspace; seq is the chain's own).

import { createHash } from "node:crypto";

export const GENESIS = Buffer.alloc(32);

export function canonical(fields: (string | null | undefined)[]): string {
  return fields.map((f) => (f === null || f === undefined ? "-1:" : `${Buffer.byteLength(f, "utf8")}:${f}`)).join("");
}

// One event as the verifier sees it: plain strings, timestamps already in the
// canonical UTC form YYYY-MM-DDTHH:MI:SS.USZ, hashes in hex.
export type RecordEvent = {
  format_version: number;
  workspace_id: string;
  // format 3: the chain this entry is on (a study's, or its workspace's)
  chain_id?: string | null;
  seq: number;
  created_at_utc: string;
  actor_id: string | null;
  actor_email: string | null;
  // format 2 and later
  actor_role?: string | null;
  session_id?: string | null;
  app_version?: string | null;
  undoes_event_id?: string | null;
  kind: string;
  study_id: string | null;
  revision_id: string | null;
  target_type: string;
  target_id: string | null;
  payload: string;
  prev_hash: string;
  hash: string;
  // an entry of another study in the same workspace, in a study's export: only
  // its hashes are given, so the chain still links but its content is not shown
  redacted?: boolean;
};

// The fields each record format hashes, in order. A format is never changed
// once used; a new one gets a new number.
export function hashedFields(e: RecordEvent): (string | null)[] {
  if (e.format_version === 1) {
    return [
      e.workspace_id,
      String(e.seq),
      e.created_at_utc,
      e.actor_id,
      e.actor_email,
      e.kind,
      e.study_id,
      e.revision_id,
      e.target_type,
      e.target_id,
      e.payload,
    ];
  }
  if (e.format_version === 2) {
    return [
      e.workspace_id,
      String(e.seq),
      e.created_at_utc,
      e.actor_id,
      e.actor_email,
      e.actor_role ?? null,
      e.session_id ?? null,
      e.app_version ?? null,
      e.kind,
      e.study_id,
      e.revision_id,
      e.target_type,
      e.target_id,
      e.undoes_event_id ?? null,
      e.payload,
    ];
  }
  if (e.format_version === 3) {
    return [
      e.chain_id ?? null,
      String(e.seq),
      e.workspace_id,
      e.created_at_utc,
      e.actor_id,
      e.actor_email,
      e.actor_role ?? null,
      e.session_id ?? null,
      e.app_version ?? null,
      e.kind,
      e.study_id,
      e.revision_id,
      e.target_type,
      e.target_id,
      e.undoes_event_id ?? null,
      e.payload,
    ];
  }
  throw new Error(`unknown record format version ${e.format_version}`);
}

export function eventHash(e: RecordEvent): Buffer {
  const text = canonical(hashedFields(e));
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from(e.prev_hash, "hex"), Buffer.from(text, "utf8")]))
    .digest();
}
