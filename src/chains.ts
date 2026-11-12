// Record file version 2 (record 2.0): one chain per study and one for the
// workspace's own entries, checked as entries arrive, each chain in order.
//
// What it checks:
// - every chain: positions from 1 with none missing, each entry linked to the
//   one before, each hash recomputed (an entry given as hashes only is linked,
//   not recomputed), and the chain ending at the head the file names;
// - entries written before the rechain (formats 1 and 2): each hash
//   recomputed; the chain's first entry, record.rechain, names how many there
//   were and sha256 over their hashes in order, and the file's earlier entries
//   must give exactly that. In a workspace's file the old chain's links and
//   its head are checked too, and its old outside timestamps;
// - the seals: each record.heads entry on the workspace's chain holds a leaf
//   sha256("<chain>:<seq>:<hash>") per study chain that had moved, so a
//   study's chain is sealed up to the highest position a leaf names;
// - the outside timestamps of the workspace's chain, each against the entry
//   it names, and each token checked with openssl.

import { createHash, type Hash } from "node:crypto";
import { GENESIS, eventHash, type RecordEvent } from "./hash.ts";
import { verifyToken } from "./tsa.ts";

export type ChainHeadV2 = {
  // null: the old chain of the workspace (record formats 1 and 2)
  chain_id: string | null;
  workspace_id: string;
  study_id: string | null;
  seq: number;
  hash: string;
};
export type AnchorV2 = {
  workspace_id: string;
  // the workspace's chain; null for an anchor of the old chain
  chain_id: string | null;
  seq: number;
  tsa: string;
  head_hash: string;
  token_base64: string;
};
// a study's file; a whole workspace's; or the workspace's own chain (export everything, beside each study's file)
export type Scope =
  | { kind: "study"; workspace_id: string; study_id: string }
  | { kind: "workspace"; workspace_id: string }
  | { kind: "own"; workspace_id: string };
export type RecordRestV2 = {
  format: "priorbase-record";
  file_version: 2;
  exported_at: string;
  scope: Scope;
  chains: ChainHeadV2[];
  anchors: AnchorV2[];
};

// a study chain sealed into its workspace's chain: up to which position, by which seal
export type Sealed = { chain_id: string; seq: number; head: number; by: number | null; anchored: number | null };

export type VerifyResultV2 = {
  problems: string[];
  chains: number;
  events: number;
  anchors: number;
  redacted: number;
  // entries written before the rechain, sealed by it
  earlier: number;
  sealed: Sealed[];
  anchorsSkipped: boolean;
};

type Chain = {
  workspace_id: string;
  study_id: string | null;
  next: number;
  // the running hash: the last entry's, as stored
  prev: string;
  // hashes by position, only those the check looks at again (see ChainsCheck's anchors)
  hashes: string[];
  // seq 1, when it is the rechain: what it seals
  rechain: { entries: number; digest: string } | null;
  // with the seals read ahead: the highest position a seal names, and its leaf
  best: { seq: number; leaf: string } | null;
};

// The seals of a record read ahead of the check (a first pass over the file,
// or one query of the database): each leaf a record.heads entry names, to the
// position of the first seal naming it, as ChainsCheck collects them.
export class SealsAhead {
  readonly seals = new Map<string, number>();
  feed(e: RecordEvent) {
    if (e.format_version !== 3 || e.redacted || e.kind !== "record.heads") return;
    const p = JSON.parse(e.payload) as { heads?: string[] };
    for (const leaf of p.heads ?? []) if (!this.seals.has(leaf)) this.seals.set(leaf, e.seq);
  }
}

export const leafOf = (chainId: string, seq: number, hash: string) =>
  createHash("sha256").update(`${chainId}:${seq}:${hash}`).digest("hex");

// A workspace's entries written before the rechain (formats 1 and 2), checked as
// they arrive in order of seq, never kept: the old chain's links and its last
// entry, and per study (null: the workspace's own) how many there were and
// sha256 over their hashes in order, which each study's rechain names.
type Legacy = {
  n: number;
  last: { seq: number; hash: string } | null;
  // the old chain's links: its running hash, and what was wrong with them
  prev: string;
  broken: boolean;
  links: string[];
  digests: Map<string | null, { n: number; sha: Hash }>;
  // hashes by position, only those the check looks at again
  at: Map<number, string>;
};

export class ChainsCheck {
  private chains = new Map<string, Chain>();
  // the old chain's entries, by workspace: positions and hashes as given
  private legacy = new Map<string, Legacy>();
  // seals on each workspace's chain: leaf to the position of the seal
  private seals = new Map<string, number>();
  private problems: string[] = [];
  private events = 0;
  private redacted = 0;
  // the seals read ahead (SealsAhead), or null. Given them, a study chain's
  // hashes are not kept, only the highest position a seal names, so memory
  // does not grow with the record. The workspace's own chain is kept whole:
  // its outside timestamps are checked against it.
  private ahead: Map<string, number> | null;
  // the positions the outside timestamps name, by chain (the old chain by
  // "old:<workspace>"), when the anchors are read ahead of the entries: only
  // those hashes are kept, so a workspace's own chain is never held whole.
  // Without them every hash of a workspace's own chain is kept, as before.
  private wanted: Map<string, Set<number>> | null;

  constructor(opts: { seals?: Map<string, number>; anchors?: AnchorV2[] } = {}) {
    this.ahead = opts.seals ?? null;
    if (opts.anchors) {
      this.wanted = new Map();
      for (const a of opts.anchors) {
        const key = a.chain_id ?? `old:${a.workspace_id}`;
        const set = this.wanted.get(key) ?? new Set<number>();
        set.add(a.seq);
        this.wanted.set(key, set);
      }
    } else this.wanted = null;
  }

  private keeps(key: string, seq: number) {
    return !this.wanted || !!this.wanted.get(key)?.has(seq);
  }

  feed(e: RecordEvent) {
    this.events++;
    if (e.redacted) this.redacted++;
    if (e.format_version !== 3) {
      if (!e.redacted) {
        let h = "";
        try {
          h = eventHash(e).toString("hex");
        } catch (err) {
          this.problems.push(`${e.workspace_id}: earlier entry ${e.seq}: ${(err as Error).message}`);
        }
        if (h !== e.hash)
          this.problems.push(`${e.workspace_id}: earlier entry ${e.seq} was altered after it was written`);
      }
      this.feedLegacy(e);
      return;
    }
    const id = e.chain_id ?? "";
    let c = this.chains.get(id);
    if (!c) {
      c = {
        workspace_id: e.workspace_id,
        study_id: e.study_id,
        next: 1,
        prev: GENESIS.toString("hex"),
        hashes: [],
        rechain: null,
        best: null,
      };
      this.chains.set(id, c);
    }
    if (e.seq !== c.next)
      this.problems.push(e.seq < c.next ? `${id}: entry ${e.seq} out of order` : `${id}: entry ${c.next} missing`);
    if (e.prev_hash !== c.prev) this.problems.push(`${id}: entry ${e.seq} does not link to the entry before it`);
    if (!e.redacted) {
      let h = "";
      try {
        h = eventHash(e).toString("hex");
      } catch (err) {
        this.problems.push(`${id}: entry ${e.seq}: ${(err as Error).message}`);
      }
      if (h !== e.hash) this.problems.push(`${id}: entry ${e.seq} was altered after it was written`);
      if (e.kind === "record.rechain" && e.seq === 1) {
        const p = JSON.parse(e.payload) as { entries?: number; digest?: string };
        c.rechain = { entries: Number(p.entries ?? 0), digest: String(p.digest ?? "") };
      }
      if (e.kind === "record.heads") {
        const p = JSON.parse(e.payload) as { heads?: string[] };
        for (const leaf of p.heads ?? []) if (!this.seals.has(leaf)) this.seals.set(leaf, e.seq);
      }
    }
    if (this.ahead && id !== e.workspace_id) {
      const leaf = leafOf(id, e.seq, e.hash);
      if (this.ahead.has(leaf) && (!c.best || e.seq > c.best.seq)) c.best = { seq: e.seq, leaf };
    } else if (id !== e.workspace_id || this.keeps(id, e.seq)) c.hashes[e.seq - 1] = e.hash;
    // the next entry links to the hash as stored, so a change is reported once
    c.prev = e.hash;
    c.next = Math.max(c.next, e.seq) + 1;
  }

  // an entry written before the rechain: the old chain's link, its study's running sha256
  private feedLegacy(e: RecordEvent) {
    const ws = e.workspace_id;
    let l = this.legacy.get(ws);
    if (!l) {
      l = {
        n: 0,
        last: null,
        prev: GENESIS.toString("hex"),
        broken: false,
        links: [],
        digests: new Map(),
        at: new Map(),
      };
      this.legacy.set(ws, l);
    }
    // in order of seq, as the file and the database give them (DECISIONS 31 October)
    if (l.last && e.seq <= l.last.seq) {
      this.problems.push(`${ws}: earlier entry ${e.seq} out of order`);
      return;
    }
    l.n++;
    if (!l.broken) {
      if (e.seq !== l.n) {
        l.links.push(`${ws}: earlier entry ${l.n} missing`);
        l.broken = true;
      } else {
        if (e.prev_hash !== l.prev) l.links.push(`${ws}: earlier entry ${e.seq} does not link to the entry before it`);
        l.prev = e.hash;
      }
    }
    const d = l.digests.get(e.study_id) ?? { n: 0, sha: createHash("sha256") };
    d.n++;
    d.sha.update(Buffer.from(e.hash, "hex"));
    l.digests.set(e.study_id, d);
    if (this.keeps(`old:${ws}`, e.seq) && !l.at.has(e.seq)) l.at.set(e.seq, e.hash);
    l.last = { seq: e.seq, hash: e.hash };
  }

  hashAt(chainId: string, seq: number): string | undefined {
    return this.chains.get(chainId)?.hashes[seq - 1];
  }

  // the highest position of a study chain a seal names, the seal, and the first timestamp after it
  sealOf(chainId: string, anchors: AnchorV2[], from = 1): Sealed | null {
    const c = this.chains.get(chainId);
    if (!c) return null;
    let best: Sealed = { chain_id: chainId, seq: 0, head: c.next - 1, by: null, anchored: null };
    if (this.ahead && chainId !== c.workspace_id) {
      // the seal as the check itself collected it, for the leaf found with the seals read ahead
      const by = c.best && c.best.seq >= from ? this.seals.get(c.best.leaf) : undefined;
      if (by !== undefined) best = { ...best, seq: c.best!.seq, by };
    } else
      for (let s = c.hashes.length; s >= from; s--) {
        const h = c.hashes[s - 1];
        if (!h) continue;
        const by = this.seals.get(leafOf(chainId, s, h));
        if (by !== undefined) {
          best = { ...best, seq: s, by };
          break;
        }
      }
    if (best.by !== null) {
      const a = anchors
        .filter((x) => x.chain_id === c.workspace_id && x.seq >= best.by!)
        .sort((x, y) => x.seq - y.seq)[0];
      best.anchored = a?.seq ?? null;
    }
    return best;
  }

  finish(rest: RecordRestV2, opts: { skipAnchors?: boolean } = {}): VerifyResultV2 {
    const problems = this.problems;
    const scope = rest.scope;
    // the seals read ahead must be the seals the check found, or a study chain's seal could be missed
    if (this.ahead) {
      const same =
        this.ahead.size === this.seals.size && [...this.seals].every(([leaf, seq]) => this.ahead!.get(leaf) === seq);
      if (!same) problems.push("the seals read ahead of the check are not the seals in the record");
    }
    // every chain ends at its head
    for (const [id, c] of this.chains) {
      const head = rest.chains.find((x) => x.chain_id === id);
      if (!head || head.seq !== c.next - 1 || head.hash !== c.prev)
        problems.push(`${id}: chain head does not match the chain`);
    }
    // the earlier entries each rechain seals
    let earlier = 0;
    for (const l of this.legacy.values()) earlier += l.n;
    for (const [id, c] of this.chains) {
      if (!c.rechain) continue;
      const own = this.legacy.get(c.workspace_id)?.digests.get(c.study_id);
      // a study's file carries the study's earlier entries, not its workspace's own
      if (c.study_id === null && scope.kind === "study") continue;
      const n = own?.n ?? 0;
      if (n !== c.rechain.entries)
        problems.push(`${id}: its rechain seals ${c.rechain.entries} earlier entries, the file has ${n}`);
      else if (c.rechain.entries > 0 && own!.sha.copy().digest("hex") !== c.rechain.digest)
        problems.push(`${id}: the earlier entries its rechain seals were changed`);
    }
    // in a workspace's file, the old chain whole: its links and its head
    if (scope.kind === "workspace") {
      for (const [ws, l] of this.legacy) {
        problems.push(...l.links);
        const head = rest.chains.find((h) => h.chain_id === null && h.workspace_id === ws);
        const last = l.last;
        if (head && (!last || head.seq !== last.seq || head.hash !== last.hash))
          problems.push(`${ws}: the old chain's head does not match its entries`);
      }
    }
    // the outside timestamps
    for (const a of rest.anchors) {
      const at = a.chain_id === null ? this.legacy.get(a.workspace_id)?.at.get(a.seq) : this.hashAt(a.chain_id, a.seq);
      if (at !== a.head_hash)
        problems.push(`${a.chain_id ?? a.workspace_id}: anchored entry ${a.seq} (${a.tsa}) no longer matches`);
      if (opts.skipAnchors) continue;
      const v = verifyToken(Buffer.from(a.token_base64, "base64"), a.head_hash);
      if (!v.ok)
        problems.push(
          `${a.chain_id ?? a.workspace_id}: ${a.tsa} token for entry ${a.seq} is invalid (${v.method}: ${v.detail})`,
        );
    }
    const sealed: Sealed[] = [];
    for (const [id, c] of this.chains) if (c.study_id !== null) sealed.push(this.sealOf(id, rest.anchors)!);
    return {
      problems,
      chains: this.chains.size,
      events: this.events,
      anchors: rest.anchors.length,
      redacted: this.redacted,
      earlier,
      sealed,
      anchorsSkipped: !!opts.skipAnchors,
    };
  }
}

// Was an entry of a study chain sealed into its workspace's chain, and that
// seal timestamped? The first outside timestamp after it, or null. An entry
// written before the rechain counts from the study chain's first position
// (its rechain seals it).
export function anchoredAfterV2(
  record: { events: RecordEvent[]; anchors: AnchorV2[] },
  e: Pick<RecordEvent, "format_version" | "chain_id" | "study_id" | "workspace_id" | "seq">,
): number | null {
  const chainId = e.format_version === 3 ? e.chain_id : e.study_id;
  if (!chainId) return null;
  const from = e.format_version === 3 ? e.seq : 1;
  const seals = new Map<string, number>();
  for (const x of record.events)
    if (x.kind === "record.heads" && !x.redacted && x.chain_id === e.workspace_id)
      for (const leaf of (JSON.parse(x.payload) as { heads?: string[] }).heads ?? [])
        if (!seals.has(leaf)) seals.set(leaf, x.seq);
  let by: number | null = null;
  for (const x of record.events) {
    if (x.chain_id !== chainId || x.seq < from) continue;
    const s = seals.get(leafOf(chainId, x.seq, x.hash));
    if (s !== undefined && (by === null || s < by)) by = s;
  }
  if (by === null) return null;
  const a = record.anchors
    .filter((x) => x.chain_id === e.workspace_id && x.seq >= by!)
    .sort((x, y) => x.seq - y.seq)[0];
  return a?.seq ?? null;
}
