Not on npm yet: `npx priorbase-verify` below will not find it until it is published.

From a clone, with Node 20 or later and nothing to install: `git clone https://github.com/OreofeOgunlude/priorbase-verify.git && cd priorbase-verify && node dist/cli.js record.json Rev2.pdf`

# priorbase-verify

Checks a Priorbase record, and the signed PDFs made from it, without trusting Priorbase. Open source (MIT), no account, no network.

```
npx priorbase-verify record.json Rev2.pdf
```

It prints `matches` or `DOES NOT MATCH` for each file, and under a mismatch exactly where it does not. Exit code 0 when everything matches, 1 when something does not, 2 when it could not run.

## What it checks

- **The record** (`record.json`, downloaded from the study's Record tab or from a workspace export): every entry is hashed with the hash of the entry before it. Since record 2.0, each study is its own chain, and a workspace's own entries (its clients, people, files) are the workspace's chain. The verifier recomputes every hash and says which entry was changed, if one was. A study's download holds that study's entries and its workspace's chain; of the workspace's chain, only the seals of study heads are shown in full, its other entries carry their hashes only, so the chain still links and nothing else is shown.
- **The rechain**: entries written before record 2.0 were one chain per workspace. They are unchanged; each chain's first entry, `record.rechain`, gives how many there were and sha256 over their hashes, and the verifier checks the file's earlier entries against it. A workspace's whole export also checks the old chain's links and its old timestamps.
- **The seals**: every six hours each study chain that moved is sealed into its workspace's chain (`record.heads`: one sha256 leaf of `<chain>:<seq>:<hash>` per study, so a seal shows nothing of another study). The verifier says how far each study's chain is sealed.
- **The outside timestamps**: the workspace chain's head is timestamped by two independent RFC 3161 authorities (DigiCert and GlobalSign). Each token is checked with `openssl ts -verify` against your machine's certificate store. `--skip-anchors` skips this; set `TSA_CA_FILE` to use a different certificate bundle.
- **A signed PDF**: its body (the report, page by page) hashes to the value in its manifest; the record holds that same body hash for that revision; the fingerprint is the one that was signed; every signer, approver and erratum the PDF names is in the record; and the signing was anchored to an outside timestamp afterwards (since record 2.0: sealed into the workspace's chain, and that seal timestamped).
- `--certificate cert.json`: an import certificate's body against its hash, and its entry in the record.

## What a match proves, and what it does not

A match proves the PDF you hold is the one that was signed and approved, and the record behind it has not changed since. It does not prove the study is correct; that is the team's judgement, printed under the signature.

## The formats

- Record file, version 2 (record 2.0): `{ format: "priorbase-record", file_version: 2, scope, events, chains, anchors }`; `scope` says whether it is one study's, a whole workspace's, or the workspace's own chain; `chains` gives each chain's head (`chain_id` empty for the old chain). Version 1, `{ format, file_version: 1, events, chain_heads, anchors }`, is still read. Each entry's hash is `sha256(prev_hash || canonical(fields))`, where the canonical form writes each field as `<byte length>:<value>` (a missing value as `-1:`), in the order given in `src/hash.ts` for the entry's `format_version` (3 adds the chain and puts it first). A format is never changed once used; this verifier checks every older one.
- Signed PDF: the document catalog's `/PriorbaseManifest` is a stream holding the manifest as JSON; each page's `/Contents` is `[body footer]`. The body hash is sha256 over each page's body stream as stored, pages in order, joined by a newline. A PDF saved again by another program is no longer the file that was signed.

Needs Node 20 or later, and openssl for the timestamps.

## Versions

- Not yet numbered (5 November): `new ChainsCheck({ anchors })` and `new ChainCheck({ anchors })` take the outside timestamps read ahead and then keep only the hashes they name, so a workspace's own chain is never held whole; entries written before the rechain are checked as they arrive (a link, a running sha256 per study, the last entry), never kept. Opt-in for the hashes: a caller that passes nothing keeps them as 2.1.0 did. The output is the same; whether this is 2.2.0 is Oreofe's call.
- 2.1.0: `new ChainsCheck({ seals })` takes the seals read ahead (`SealsAhead`) and then keeps no hash for each entry of a study chain, so memory does not grow with the record. Opt-in: a caller that passes nothing checks exactly as 2.0.0 did, and every export 2.0.0 accepted is still accepted (the repository's tests keep one made before 2.1.0).
- 2.0.0: record 2.0 (one chain per study, sealed into the workspace's chain).
