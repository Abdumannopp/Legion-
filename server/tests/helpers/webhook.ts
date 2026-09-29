/**
 * Test helpers for the sensor webhook: obtain a real credential for a tenant
 * and send requests signed exactly as integrations/custom-legion.py signs them.
 */
import request from "supertest";
import type { Application } from "express";
import { randomBytes } from "node:crypto";
import { createCredential } from "../../src/webhook-credentials.js";
import { signWebhook } from "../../src/webhook-auth.js";

export interface TestCredential { keyId: string; secret: string; apiKey: string }

export async function issueCredential(tenantId: string, label = "test"): Promise<TestCredential> {
  const c = await createCredential(tenantId, { label });
  return { keyId: c.id, secret: c.secret, apiKey: c.api_key };
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);
export const freshNonce = () => randomBytes(16).toString("base64url");

export interface SendOptions {
  timestamp?: number;
  nonce?: string;
  /** Sign with a different secret than the credential's (a forgery). */
  signWithSecret?: string;
  /** Sign different bytes than are sent (a body tampered in transit). */
  signBody?: string;
  /** Override the key id header. */
  keyId?: string;
  /** Add the old, untrusted x-tenant-id header. */
  tenantHeader?: string;
}

/** POSTs `body` (a string is sent byte-for-byte) signed with `cred`. */
export function sendSigned(app: Application, cred: TestCredential, body: unknown, opts: SendOptions = {}) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  const ts = String(opts.timestamp ?? nowSeconds());
  const nonce = opts.nonce ?? freshNonce();
  const req = request(app)
    .post("/security-events/webhook")
    .set("content-type", "application/json")
    .set("x-legion-key-id", opts.keyId ?? cred.keyId)
    .set("x-legion-timestamp", ts)
    .set("x-legion-nonce", nonce)
    .set("x-legion-signature", signWebhook(opts.signWithSecret ?? cred.secret, ts, nonce, opts.signBody ?? raw));
  if (opts.tenantHeader) req.set("x-tenant-id", opts.tenantHeader);
  return req.send(raw);
}
