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
export declare function checkPdf(pdf: PdfRead, record: AnyRecordFile | null): PdfCheck;
