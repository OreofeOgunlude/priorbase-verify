// RFC 3161 timestamps: asking an authority to stamp a hash, and proving a
// stamp is genuine. Shells out to openssl, which every verifier will have.

import { execFileSync, type ExecFileSyncOptions } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type Tsa = { name: string; url: string };

// Two independent authorities, both verifiable with `openssl ts -verify`.
// GlobalSign replaced Sectigo on 2026-10-10 (Sectigo's tokens fail OpenSSL's
// one-step check).
export const TSAS: Tsa[] = [
  { name: "digicert", url: "http://timestamp.digicert.com" },
  { name: "globalsign", url: "http://timestamp.globalsign.com/tsa/r6advanced1" },
];

export function caFile(): string {
  if (process.env.TSA_CA_FILE) return process.env.TSA_CA_FILE;
  for (const f of ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"])
    if (existsSync(f)) return f;
  const out = execFileSync("openssl", ["version", "-d"], { encoding: "utf8" });
  const dir = out.match(/"(.*)"/)?.[1];
  if (!dir) throw new Error("cannot find the openssl certificate directory; set TSA_CA_FILE");
  return join(dir, "cert.pem");
}

function openssl(args: string[], opts: ExecFileSyncOptions = {}): string {
  return execFileSync("openssl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts }) as string;
}

function withTmp<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "tsa-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function errText(err: unknown): string {
  const e = err as { stderr?: unknown };
  return String(e?.stderr ?? err).trim();
}

// Reads the hashed message and the time out of a token.
function tokenFacts(tokenPath: string): { imprint: string; genTime: Date } {
  const text = openssl(["ts", "-reply", "-token_in", "-in", tokenPath, "-text"]);
  const block = text.split("Message data:")[1]?.split(/\n\S/)[0] ?? "";
  const imprint = [...block.matchAll(/^\s+[0-9a-f]{4} - (.*?)\s{2,}/gim)]
    .map((m) => m[1].replace(/[^0-9a-f]/gi, ""))
    .join("")
    .toLowerCase();
  const m = text.match(/Time stamp: (\w{3})\s+(\d+) (\d\d:\d\d:\d\d(?:\.\d+)?) (\d{4}) GMT/);
  if (!m) throw new Error("token has no readable time stamp");
  return { imprint, genTime: new Date(`${m[1]} ${m[2]} ${m[4]} ${m[3]} GMT`) };
}

export type TokenCheck = { ok: boolean; method: string; genTime: Date; detail?: string };

// Proves a token is a genuine, unaltered timestamp of exactly this hash. The
// two-step fallback (CMS signature and chain, then the hashed message) is kept
// for tokens from authorities whose certificate reference OpenSSL 3 rejects.
export function verifyToken(tokenDer: Buffer, hexDigest: string): TokenCheck {
  return withTmp((dir) => {
    const tok = join(dir, "token.der");
    writeFileSync(tok, tokenDer);
    let facts: { imprint: string; genTime: Date };
    try {
      facts = tokenFacts(tok);
    } catch (err) {
      // a damaged token cannot even be read; it proves nothing
      return { ok: false, method: "read", genTime: new Date(0), detail: errText(err) || "the token cannot be read" };
    }
    if (facts.imprint !== hexDigest.toLowerCase()) {
      return { ok: false, method: "imprint", genTime: facts.genTime, detail: "token is for a different hash" };
    }
    try {
      openssl(["ts", "-verify", "-digest", hexDigest, "-token_in", "-in", tok, "-CAfile", caFile()]);
      return { ok: true, method: "ts-verify", genTime: facts.genTime };
    } catch (err) {
      if (!/ess cert id not found/i.test(errText(err))) {
        return { ok: false, method: "ts-verify", genTime: facts.genTime, detail: errText(err) };
      }
    }
    try {
      openssl([
        "cms",
        "-verify",
        "-inform",
        "DER",
        "-in",
        tok,
        "-CAfile",
        caFile(),
        "-purpose",
        "timestampsign",
        "-out",
        join(dir, "content"),
      ]);
      return { ok: true, method: "cms-signature+imprint", genTime: facts.genTime };
    } catch (err) {
      return { ok: false, method: "cms-signature", genTime: facts.genTime, detail: errText(err) };
    }
  });
}

// Asks one authority to timestamp a SHA-256 hash; returns the verified token.
export async function stamp(hexDigest: string, tsa: Tsa): Promise<{ token: Buffer; genTime: Date; method: string }> {
  const query = withTmp((dir) => {
    const q = join(dir, "q.tsq");
    openssl(["ts", "-query", "-digest", hexDigest, "-sha256", "-cert", "-out", q]);
    return readFileSync(q);
  });
  const res = await fetch(tsa.url, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: query,
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`${tsa.name}: HTTP ${res.status}`);
  const reply = Buffer.from(await res.arrayBuffer());
  const token = withTmp((dir) => {
    const r = join(dir, "r.tsr");
    const t = join(dir, "t.der");
    writeFileSync(r, reply);
    const status = openssl(["ts", "-reply", "-in", r, "-text"]);
    if (!/Status: Granted/.test(status)) throw new Error(`${tsa.name}: request not granted`);
    openssl(["ts", "-reply", "-in", r, "-token_out", "-out", t]);
    return readFileSync(t);
  });
  const check = verifyToken(token, hexDigest);
  if (!check.ok) throw new Error(`${tsa.name}: token failed verification (${check.method}: ${check.detail})`);
  return { token, genTime: check.genTime, method: check.method };
}
