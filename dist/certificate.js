// Checks an import certificate offline: its hash is sha256 of its body, and
// the record holds an "import.certified" entry with that hash and number, or
// an "import.certificate_renumbered" entry that gives them (0034 renumbered the
// sample certificates; their first entry keeps the old number and hash).
// The body is checked exactly as stored, byte for byte; nothing is re-encoded.
import { createHash } from "node:crypto";
export const CERTIFICATE_FORMAT = "priorbase-import-certificate";
export function verifyCertificate(cert, record) {
    const problems = [];
    const actual = createHash("sha256").update(cert.body, "utf8").digest("hex");
    if (actual !== cert.certificate_hash) {
        problems.push(`${cert.certificate_number}: the body does not match the certificate hash; it was changed`);
    }
    let body;
    try {
        body = JSON.parse(cert.body);
    }
    catch {
        return [...problems, `${cert.certificate_number}: the body is not readable JSON`];
    }
    if (body.format !== CERTIFICATE_FORMAT)
        problems.push(`${cert.certificate_number}: not a ${CERTIFICATE_FORMAT}`);
    if (body.certificate_number !== cert.certificate_number) {
        problems.push(`${cert.certificate_number}: the body names a different certificate (${body.certificate_number})`);
    }
    if (record) {
        const entry = record.events.find((e) => {
            if (e.kind !== "import.certified" && e.kind !== "import.certificate_renumbered")
                return false;
            const p = JSON.parse(e.payload);
            return p.certificate_number === cert.certificate_number && p.certificate_hash === cert.certificate_hash;
        });
        if (!entry)
            problems.push(`${cert.certificate_number}: the record has no certified entry with this hash`);
    }
    return problems;
}
