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
export function canonical(fields) {
    return fields.map((f) => (f === null || f === undefined ? "-1:" : `${Buffer.byteLength(f, "utf8")}:${f}`)).join("");
}
// The fields each record format hashes, in order. A format is never changed
// once used; a new one gets a new number.
export function hashedFields(e) {
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
export function eventHash(e) {
    const text = canonical(hashedFields(e));
    return createHash("sha256")
        .update(Buffer.concat([Buffer.from(e.prev_hash, "hex"), Buffer.from(text, "utf8")]))
        .digest();
}
