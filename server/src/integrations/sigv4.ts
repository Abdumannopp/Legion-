/** AWS Signature Version 4 for JSON APIs, no SDK. Verified against AWS's published test vector (tests). */
import { createHash, createHmac } from "node:crypto";

const hmac = (key: Buffer | string, data: string) => createHmac("sha256", key).update(data).digest();
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export interface SignInput {
  method: string; host: string; path: string; query?: Record<string, string>; body?: string;
  region: string; service: string; accessKeyId: string; secretAccessKey: string; sessionToken?: string;
  /** For tests only. */ now?: Date;
}

export function signV4(i: SignInput): Record<string, string> {
  const d = (i.now ?? new Date()).toISOString().replace(/[:-]|\.\d{3}/g, ""); // 20150830T123600Z
  const day = d.slice(0, 8);
  const body = i.body ?? "";
  const headers: Record<string, string> = { host: i.host, "x-amz-date": d, ...(i.sessionToken ? { "x-amz-security-token": i.sessionToken } : {}) };
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((n) => `${n}:${headers[n]!.trim()}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalQuery = Object.entries(i.query ?? {}).map(([k, v]) => [enc(k), enc(v)] as const).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join("&");
  const canonical = [i.method, i.path, canonicalQuery, canonicalHeaders, signedHeaders, sha(body)].join("\n");
  const scope = `${day}/${i.region}/${i.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", d, scope, sha(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${i.secretAccessKey}`, day), i.region), i.service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  return {
    "x-amz-date": d, ...(i.sessionToken ? { "x-amz-security-token": i.sessionToken } : {}),
    authorization: `AWS4-HMAC-SHA256 Credential=${i.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}
