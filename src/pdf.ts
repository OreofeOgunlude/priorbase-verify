// Reading a signed Priorbase PDF: its manifest and the hash of its body.
//
// Layout (written by Priorbase's PDF writer, never compressed):
//   - the catalog has /PriorbaseManifest pointing at a stream whose content is
//     the manifest as JSON;
//   - each page's /Contents is [body footer]; the body stream is the report,
//     the footer stream is the manifest as printed.
// The body hash is sha256 over each page's body stream, exactly as stored,
// pages in order, joined by a single newline. A PDF saved again by another
// program (re-compressed, re-ordered) is no longer the file that was signed,
// and says so.

import { createHash } from "node:crypto";

export const MANIFEST_FORMAT = "priorbase-manifest";

export type Manifest = {
  format: typeof MANIFEST_FORMAT;
  version: 1;
  workspace_id: string;
  study_id: string;
  study: string;
  revision_id: string;
  rev: number;
  fingerprint: string;
  fingerprint_version: number;
  body_sha256: string;
  signed: { name: string; credential: string | null; at: string; method: string };
  // final: the approver who approved last (manifests from verifier 1.2.0 on)
  approvals: { name: string; credential: string | null; at: string; method: string; final?: boolean }[];
  errata: { at: string; text: string; reason: string }[];
};

export type PdfRead = { manifest: Manifest | null; bodySha256: string | null; pages: number; problem: string | null };

type Obj = { dict: string; stream: string | null };

function objects(text: string): Map<number, Obj> {
  const out = new Map<number, Obj>();
  const re = /(\d+) 0 obj\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const start = m.index + m[0].length;
    const s = text.indexOf("stream\n", start);
    const end = text.indexOf("\nendobj", start);
    if (end < 0) break;
    if (s >= 0 && s < end) {
      const dict = text.slice(start, s);
      const len = Number(/\/Length (\d+)/.exec(dict)?.[1] ?? -1);
      const body = len >= 0 ? text.slice(s + 7, s + 7 + len) : null;
      out.set(Number(m[1]), { dict, stream: body });
      re.lastIndex = Math.max(re.lastIndex, s + 7 + Math.max(len, 0));
    } else {
      out.set(Number(m[1]), { dict: text.slice(start, end), stream: null });
      re.lastIndex = end;
    }
  }
  return out;
}

const ref = (dict: string, key: string) => {
  const m = new RegExp(`/${key} (\\d+) 0 R`).exec(dict);
  return m ? Number(m[1]) : null;
};

export function readPdf(bytes: Uint8Array): PdfRead {
  let text = "";
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]!);
  if (!text.startsWith("%PDF-")) return { manifest: null, bodySha256: null, pages: 0, problem: "not a PDF" };
  const objs = objects(text);
  const catalog = [...objs.values()].find((o) => /\/Type \/Catalog/.test(o.dict));
  if (!catalog) return { manifest: null, bodySha256: null, pages: 0, problem: "this PDF has no catalog we can read" };
  const mRef = ref(catalog.dict, "PriorbaseManifest");
  const pagesRef = ref(catalog.dict, "Pages");
  const kids = [
    ...(/\/Kids \[([^\]]*)\]/.exec(objs.get(pagesRef ?? -1)?.dict ?? "")?.[1] ?? "").matchAll(/(\d+) 0 R/g),
  ].map((k) => Number(k[1]));
  let manifest: Manifest | null = null;
  const mStream = mRef !== null ? objs.get(mRef)?.stream : null;
  if (mStream) {
    try {
      manifest = JSON.parse(mStream) as Manifest;
    } catch {
      return { manifest: null, bodySha256: null, pages: kids.length, problem: "the manifest in this PDF is damaged" };
    }
  }
  const bodies: string[] = [];
  for (const k of kids) {
    const contents = /\/Contents \[(\d+) 0 R (\d+) 0 R\]/.exec(objs.get(k)?.dict ?? "");
    const body = contents ? objs.get(Number(contents[1]))?.stream : null;
    if (body === null || body === undefined)
      return {
        manifest,
        bodySha256: null,
        pages: kids.length,
        problem: "a page of this PDF is not laid out as Priorbase writes it",
      };
    bodies.push(body);
  }
  const h = createHash("sha256");
  h.update(Buffer.from(bodies.join("\n"), "latin1"));
  return {
    manifest,
    bodySha256: kids.length ? h.digest("hex") : null,
    pages: kids.length,
    problem: manifest ? null : "this PDF has no Priorbase manifest: it is a draft, or it was not made by Priorbase",
  };
}
