import type { AnyRecordFile } from "./verify.ts";
export declare const CERTIFICATE_FORMAT = "priorbase-import-certificate";
export type CertificateFile = {
    certificate_number: string;
    certificate_hash: string;
    body: string;
};
export declare function verifyCertificate(cert: CertificateFile, record?: AnyRecordFile): string[];
