// A signed PDF against the record: the body is the one in the manifest, the
// manifest is the one the record holds, the fingerprint is the one that was
// signed, every signer and approver it names is in the record, and the
// signing was anchored to an outside timestamp afterwards.

import { anchoredAfterV2 } from "./chains.ts";
import type { RecordEvent } from "./hash.ts";
import type { PdfRead } from "./pdf.ts";
import type { AnyRecordFile } from "./verify.ts";

export type PdfCheck = {
  problems: string[];
  study: string | null;
  rev: number | null;
  fingerprint: string | null;
  signedSeq: number | null;
  anchoredSeq: number | null;
};

type Payload = { new?: Record<string, unknown> } & Record<string, unknown>;
const payloadOf = (e: RecordEvent): Payload => {
  try {
    return JSON.parse(e.payload) as Payload;
  } catch {
    return {};
  }
};

export function checkPdf(pdf: PdfRead, record: AnyRecordFile | null): PdfCheck {
  const problems: string[] = [];
  const m = pdf.manifest;
  const out: PdfCheck = {
    problems,
    study: m?.study ?? null,
    rev: m?.rev ?? null,
    fingerprint: m?.fingerprint ?? null,
    signedSeq: null,
    anchoredSeq: null,
  };
  if (pdf.problem) problems.push(pdf.problem);
  if (!m) return out;
  if (pdf.bodySha256 !== m.body_sha256)
    problems.push("the body of this PDF is not the body its manifest names: it was changed after it was made");
  if (!record) return out;

  const forRev = record.events.filter((e) => !e.redacted && e.revision_id === m.revision_id);
  const signedEv = forRev.find((e) => e.kind === "revision.signed");
  if (!signedEv) {
    problems.push(`the record holds no signature for revision ${m.rev} of ${m.study}`);
    return out;
  }
  out.signedSeq = signedEv.seq;
  const sp = payloadOf(signedEv);
  if (sp.fingerprint !== m.fingerprint) problems.push("the fingerprint in this PDF is not the one in the record");
  const body = forRev.find((e) => e.kind === "signed_reports.insert");
  if (!body) problems.push("the record holds no body hash for this revision");
  else if (payloadOf(body).new?.body_sha256 !== m.body_sha256)
    problems.push("the record holds a different body for this revision");

  const sigs = forRev.filter((e) => e.kind === "signatures.insert").map((e) => payloadOf(e).new ?? {});
  const has = (kind: string, name: string, fp: string, role?: string) =>
    sigs.some((s) => s.kind === kind && s.stated_name === name && s.fingerprint === fp && (!role || s.role === role));
  if (!has("signed", m.signed.name, m.fingerprint)) problems.push(`the record holds no signature by ${m.signed.name}`);
  for (const a of m.approvals)
    if (!has("approved", a.name, m.fingerprint)) problems.push(`the record holds no approval by ${a.name}`);
    else if (a.final && !has("approved", a.name, m.fingerprint, "final approver"))
      problems.push(`the record does not hold ${a.name} as the final approver`);
  const errata = forRev.filter((e) => e.kind === "errata.insert").map((e) => payloadOf(e).new ?? {});
  for (const x of m.errata)
    if (!errata.some((e) => e.text === x.text)) problems.push(`the record holds no erratum "${x.text}"`);

  if (record.file_version === 2) {
    // record 2.0: the signing is anchored once a seal of the study's chain at or after it is timestamped
    out.anchoredSeq = anchoredAfterV2(record, signedEv);
    return out;
  }
  const anchored = record.anchors
    .filter((a) => a.workspace_id === signedEv.workspace_id && a.seq >= signedEv.seq)
    .sort((a, b) => a.seq - b.seq)[0];
  out.anchoredSeq = anchored?.seq ?? null;
  return out;
}
