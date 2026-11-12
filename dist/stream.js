// The record read entry by entry (Phase 7c): a long-lived workspace's record
// is hundreds of megabytes, more than one string can hold, so the file is
// never read whole. A small scanner walks the JSON as it streams in, hands
// each entry of "events" over on its own, and keeps only the rest of the file
// (format, chain heads, anchors), which is small. It reads any layout of the
// same JSON: one entry per line as the export writes it, or pretty printed.
// The chain is checked as the entries arrive (ChainCheck), so memory holds
// each chain's running hash, not the entries.
import { GENESIS, eventHash } from "./hash.js";
import { verifyToken } from "./tsa.js";
import { RECORD_FILE_FORMAT, } from "./verify.js";
// Walks JSON text chunk by chunk; each element of the top-level "events" array goes to onEvent.
export class RecordScanner {
    depth = 0;
    inString = false;
    escape = false;
    head = [];
    str = [];
    lastString = null;
    pendingKey = null;
    inEvents = false;
    element = null;
    onEvent;
    constructor(onEvent) {
        this.onEvent = onEvent;
    }
    write(text) {
        let from = 0;
        for (let i = 0; i < text.length; i++) {
            const c = text[i];
            if (this.inString) {
                const top = !this.inEvents && this.depth === 1;
                if (this.escape)
                    this.escape = false;
                else if (c === "\\")
                    this.escape = true;
                else if (c === '"') {
                    this.inString = false;
                    // a key or a value at the top level has just ended
                    if (top)
                        this.lastString = this.str.join("");
                    continue;
                }
                if (top)
                    this.str.push(c);
                continue;
            }
            if (c === '"') {
                this.inString = true;
                if (!this.inEvents && this.depth === 1)
                    this.str = [];
                continue;
            }
            if (this.inEvents) {
                if (c === "{" || c === "[") {
                    if (this.depth === 2 && c === "{") {
                        this.element = [];
                        from = i;
                    }
                    this.depth++;
                }
                else if (c === "}" || c === "]") {
                    this.depth--;
                    if (this.depth === 2 && this.element) {
                        this.element.push(text.slice(from, i + 1));
                        this.onEvent(JSON.parse(this.element.join("")));
                        this.element = null;
                    }
                    else if (this.depth === 1) {
                        // the end of "events": the rest of the file goes on into head
                        this.inEvents = false;
                        this.head.push("]");
                        from = i + 1;
                        continue;
                    }
                }
                continue;
            }
            if (c === "{" || c === "[") {
                this.depth++;
                if (this.depth === 2 && c === "[" && this.pendingKey === "events") {
                    this.head.push(text.slice(from, i + 1));
                    this.inEvents = true;
                    this.pendingKey = null;
                    continue;
                }
            }
            else if (c === "}" || c === "]")
                this.depth--;
            else if (c === ":" && this.depth === 1)
                this.pendingKey = this.lastString;
            else if (c === "," && this.depth === 1)
                this.pendingKey = null;
        }
        if (this.inEvents) {
            if (this.element)
                this.element.push(text.slice(from));
        }
        else
            this.head.push(text.slice(from));
    }
    // what was not an entry: format, version, chain heads, anchors
    end() {
        if (this.inEvents || this.depth !== 0)
            throw new Error("the record file ends in the middle");
        return JSON.parse(this.head.join(""));
    }
}
// Read a record from text chunks: each entry to onEvent, the rest returned.
export async function readRecord(chunks, onEvent) {
    const scanner = new RecordScanner(onEvent);
    const decoder = new TextDecoder();
    for await (const c of chunks)
        scanner.write(typeof c === "string" ? c : decoder.decode(c, { stream: true }));
    scanner.write(decoder.decode());
    return scanner.end();
}
// The chain checked as entries arrive, each workspace's in order of seq: its
// running hash and last position. Given the anchors ahead of the entries (the
// record's and the copies kept outside), only the hashes they name are kept;
// without them every hash, as before.
export class ChainCheck {
    chains = new Map();
    problems = [];
    events = 0;
    redacted = 0;
    wanted = null;
    constructor(opts = {}) {
        if (!opts.anchors)
            return;
        this.wanted = new Map();
        for (const a of opts.anchors) {
            const set = this.wanted.get(a.workspace_id) ?? new Set();
            set.add(a.seq);
            this.wanted.set(a.workspace_id, set);
        }
    }
    feed(e) {
        this.events++;
        if (e.redacted)
            this.redacted++;
        let c = this.chains.get(e.workspace_id);
        if (!c) {
            c = { next: 1, prev: GENESIS.toString("hex"), hashes: [] };
            this.chains.set(e.workspace_id, c);
        }
        const ws = e.workspace_id;
        if (e.seq !== c.next) {
            this.problems.push(e.seq < c.next ? `${ws}: entry ${e.seq} out of order` : `${ws}: entry ${c.next} missing`);
        }
        if (e.prev_hash !== c.prev)
            this.problems.push(`${ws}: entry ${e.seq} does not link to the entry before it`);
        if (!e.redacted) {
            let h = "";
            try {
                h = eventHash(e).toString("hex");
            }
            catch (err) {
                this.problems.push(`${ws}: entry ${e.seq}: ${err.message}`);
            }
            if (h !== e.hash)
                this.problems.push(`${ws}: entry ${e.seq} was altered after it was written`);
        }
        if (!this.wanted || this.wanted.get(ws)?.has(e.seq))
            c.hashes[e.seq - 1] = e.hash;
        // the next entry links to the hash as stored, so a change is reported at
        // the entry that was changed, not again at every entry after it
        c.prev = e.hash;
        c.next = Math.max(c.next, e.seq) + 1;
    }
    hashAt(ws, seq) {
        return this.chains.get(ws)?.hashes[seq - 1];
    }
    finish(rest, external = [], opts = {}) {
        const problems = this.problems;
        if (rest.format !== RECORD_FILE_FORMAT || rest.file_version !== 1)
            return {
                problems: [`not a ${RECORD_FILE_FORMAT} file version 1`],
                chains: 0,
                events: 0,
                anchors: 0,
                external: 0,
                redacted: 0,
                anchorsSkipped: !!opts.skipAnchors,
            };
        for (const [ws, c] of this.chains) {
            const head = rest.chain_heads.find((x) => x.workspace_id === ws);
            if (!head || head.seq !== c.next - 1 || head.hash !== c.prev)
                problems.push(`${ws}: chain head does not match the chain`);
        }
        for (const a of rest.anchors) {
            if (this.hashAt(a.workspace_id, a.seq) !== a.head_hash)
                problems.push(`${a.workspace_id}: anchored entry ${a.seq} (${a.tsa}) no longer matches`);
            if (opts.skipAnchors)
                continue;
            const v = verifyToken(Buffer.from(a.token_base64, "base64"), a.head_hash);
            if (!v.ok)
                problems.push(`${a.workspace_id}: ${a.tsa} token for entry ${a.seq} is invalid (${v.method}: ${v.detail})`);
        }
        for (const x of external) {
            const inRecord = rest.anchors.find((a) => a.workspace_id === x.workspace_id && a.seq === x.seq && a.tsa === x.tsa);
            if (!inRecord)
                problems.push(`${x.workspace_id}: external anchor ${x.seq}-${x.tsa} is missing from the record`);
            else if (inRecord.token_base64 !== x.token_base64)
                problems.push(`${x.workspace_id}: external anchor ${x.seq}-${x.tsa} differs from the record's copy`);
            if (this.hashAt(x.workspace_id, x.seq) !== x.head_hash)
                problems.push(`${x.workspace_id}: external anchor ${x.seq}-${x.tsa} no longer matches the chain`);
        }
        return {
            problems,
            chains: this.chains.size,
            events: this.events,
            anchors: rest.anchors.length,
            external: external.length,
            redacted: this.redacted,
            anchorsSkipped: !!opts.skipAnchors,
        };
    }
}
