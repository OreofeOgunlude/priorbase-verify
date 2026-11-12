#!/usr/bin/env node
// priorbase-verify: checks a Priorbase record and the signed PDFs made from
// it, without trusting Priorbase. Needs Node and, for the outside timestamps,
// openssl; no network.
//
//   npx priorbase-verify record.json [Rev2.pdf ...] [--skip-anchors] [--certificate cert.json]
//
// Prints what matches, or exactly where it does not. Exit code 0 when
// everything matches, 1 when something does not, 2 when it could not run.

import { closeSync, createReadStream, openSync, readFileSync, readSync } from "node:fs";
import { ChainsCheck, type RecordRestV2 } from "./chains.ts";
import { verifyCertificate, type CertificateFile } from "./certificate.ts";
import { checkPdf } from "./check.ts";
import { readPdf } from "./pdf.ts";
import type { RecordEvent } from "./hash.ts";
import { ChainCheck, readRecord } from "./stream.ts";
import type { AnyRecordFile, RecordFile } from "./verify.ts";

export const VERSION = "2.1.0";

const args = process.argv.slice(2);
if (args.includes("--version")) {
  console.log(VERSION);
  process.exit(0);
}
const skipAnchors = args.includes("--skip-anchors");
const certIdx = args.indexOf("--certificate");
const certPath = certIdx >= 0 ? args[certIdx + 1] : undefined;
const files = args.filter((a, i) => !a.startsWith("--") && !(certIdx >= 0 && i === certIdx + 1));
const recordPath = files.find((f) => /\.json$/i.test(f));
const pdfs = files.filter((f) => /\.pdf$/i.test(f));
if (!recordPath && !pdfs.length) {
  console.error("usage: priorbase-verify record.json [signed.pdf ...] [--skip-anchors] [--certificate cert.json]");
  process.exit(2);
}

let bad = false;
const say = (ok: boolean, line: string) => {
  if (!ok) bad = true;
  console.log(`${ok ? "matches" : "DOES NOT MATCH"}  ${line}`);
};

// the file's version, from its first line (both writers put it there)
function fileVersion(path: string): number {
  const fd = openSync(path, "r");
  const buf = Buffer.alloc(4096);
  const n = readSync(fd, buf, 0, buf.length, 0);
  closeSync(fd);
  return Number(/"file_version"\s*:\s*(\d+)/.exec(buf.subarray(0, n).toString("utf8"))?.[1] ?? 1);
}

let record: AnyRecordFile | null = null;
if (recordPath && fileVersion(recordPath) === 2) {
  // record 2.0: one chain per study, sealed into the workspace's chain
  const check = new ChainsCheck();
  const keep = pdfs.length > 0 || !!certPath;
  const kept: RecordEvent[] = [];
  let rest;
  try {
    rest = (await readRecord(createReadStream(recordPath), (e) => {
      check.feed(e);
      if (keep && (!e.redacted || e.kind === "record.heads")) kept.push(e);
    })) as unknown as RecordRestV2;
  } catch (e) {
    console.error(`${recordPath}: not a record file (${(e as Error).message})`);
    process.exit(2);
  }
  record = { ...rest, events: kept };
  const r = check.finish(rest, { skipAnchors });
  const sealed = r.sealed.filter((x) => x.by !== null);
  const anchored = r.sealed.filter((x) => x.anchored !== null);
  say(
    r.problems.length === 0,
    `record: ${r.events} entries in ${r.chains} ${r.chains === 1 ? "chain" : "chains"}${r.earlier ? ` (${r.earlier} written before the rechain, sealed by it)` : ""}${r.redacted ? `, ${r.redacted} of the workspace's own given as hashes only` : ""}; ${sealed.length} of ${r.sealed.length} study ${r.sealed.length === 1 ? "chain" : "chains"} sealed into the workspace's chain, ${anchored.length} anchored; ${
      r.anchorsSkipped
        ? `${r.anchors} outside timestamps not checked (--skip-anchors)`
        : `${r.anchors} outside timestamps checked`
    }`,
  );
  for (const p of r.problems) console.log(`    ${p}`);
} else if (recordPath) {
  // read entry by entry: a record can be larger than one string can hold
  const check = new ChainCheck();
  // the PDFs and the certificate look at entries; only then are they kept
  const keep = pdfs.length > 0 || !!certPath;
  const kept: RecordEvent[] = [];
  let rest;
  try {
    rest = await readRecord(createReadStream(recordPath), (e) => {
      check.feed(e);
      if (keep && !e.redacted) kept.push(e);
    });
  } catch (e) {
    console.error(`${recordPath}: not a record file (${(e as Error).message})`);
    process.exit(2);
  }
  record = { ...rest, events: kept } as RecordFile;
  const r = check.finish(rest, [], { skipAnchors });
  say(
    r.problems.length === 0,
    `record: ${r.events} entries in ${r.chains} ${r.chains === 1 ? "chain" : "chains"}${r.redacted ? ` (${r.redacted} of another study given as hashes only)` : ""}, ${
      r.anchorsSkipped
        ? `${r.anchors} outside timestamps not checked (--skip-anchors)`
        : `${r.anchors} outside timestamps checked`
    }`,
  );
  for (const p of r.problems) console.log(`    ${p}`);
}

for (const path of pdfs) {
  const pdf = readPdf(new Uint8Array(readFileSync(path)));
  const c = checkPdf(pdf, record);
  const m = pdf.manifest;
  if (!m) {
    say(false, `${path}: ${pdf.problem}`);
    continue;
  }
  const who = [
    `signed by ${m.signed.name} on ${m.signed.at.slice(0, 10)}`,
    ...m.approvals.map((a) => `approved by ${a.name} on ${a.at.slice(0, 10)}${a.final ? " (final approver)" : ""}`),
  ].join(", ");
  say(
    c.problems.length === 0,
    `${path}: ${m.study}, Rev ${m.rev}, ${who}, fingerprint ${m.fingerprint}${
      record
        ? c.anchoredSeq !== null
          ? `, anchored after signing (entry ${c.anchoredSeq})`
          : ", not anchored yet"
        : ", record not given: body checked against its manifest only"
    }`,
  );
  for (const p of c.problems) console.log(`    ${p}`);
}

if (certPath) {
  const cert = JSON.parse(readFileSync(certPath, "utf8")) as CertificateFile;
  const problems = verifyCertificate(cert, record ?? undefined);
  say(problems.length === 0, `${certPath}: import certificate ${cert.certificate_number}`);
  for (const p of problems) console.log(`    ${p}`);
}

process.exit(bad ? 1 : 0);
