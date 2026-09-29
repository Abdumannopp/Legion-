/*
 * Category: Secret access — an attacker (an outside caller, a compromised
 * agent, or careless policy) tries to reach credentials, tokens, or other
 * secret material directly, or tries to slip a secret through in a
 * request/argument/log where it would leak.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import request from "supertest";
import { describe } from "vitest";
import { as, bearer } from "../test/helpers.js";
import { authorize, brief, mkAgent, setPolicy, SLACK, useWorld } from "./setup.js";
import { defended, notDefended, partial, scenario } from "./harness.js";

const w = useWorld();

describe("Secret access", () => {
  scenario({
    id: "SA-1",
    category: "Secret access",
    title: "Credential guessing does not reveal whether an identity exists",
    attackPath: "An attacker who has learned (or guessed) a real credential id tries a wrong secret against it, then compares the response with a wholly made-up credential id, hoping to distinguish \"exists but wrong secret\" from \"doesn't exist\" to enumerate valid credential ids.",
    expectedDefense: "Both cases return the identical generic invalid_credential response; only the internal audit trail (not visible to the caller) distinguishes them.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    // "lga_" matches the ai_agent kind mkAgent actually created — using the wrong
    // prefix would hit credential_kind_mismatch instead of the bad-secret path.
    const realCredentialIdHex = a.credentialId.replace(/-/g, "");
    const wrongSecretOnRealId = await request(w.t.app).post("/agent/v1/token")
      .set("authorization", `Bearer lga_${realCredentialIdHex}_${"x".repeat(43)}`);
    const madeUpIdHex = "0".repeat(32);
    const madeUpCredential = await request(w.t.app).post("/agent/v1/token")
      .set("authorization", `Bearer lga_${madeUpIdHex}_${"x".repeat(43)}`);
    ev("wrongSecretOnRealId", { status: wrongSecretOnRealId.status, body: wrongSecretOnRealId.body });
    ev("madeUpCredentialId", { status: madeUpCredential.status, body: madeUpCredential.body });
    const identical = wrongSecretOnRealId.status === madeUpCredential.status
      && JSON.stringify(wrongSecretOnRealId.body) === JSON.stringify(madeUpCredential.body);
    return identical
      ? defended(`Both return identical ${wrongSecretOnRealId.status} ${JSON.stringify(wrongSecretOnRealId.body.error)}.`)
      : notDefended(`Responses differ: ${JSON.stringify(wrongSecretOnRealId.body)} vs ${JSON.stringify(madeUpCredential.body)}`, "Medium", "Return the same generic error for a wrong secret and a nonexistent credential id.");
  });

  scenario({
    id: "SA-2",
    category: "Secret access",
    title: "Admin tries to open Legion's own secret tables to agents via policy",
    attackPath: "An administrator (possibly tricked by a compromised or malicious agent's suggestion) tries to set firewall policy so agents can query machine_credentials, machine_tokens, agent_delegations or principal_audit_log directly through the database tool.",
    expectedDefense: "The policy schema itself refuses to accept any protected table name, independent of admin intent — this cannot be misconfigured into existence.",
  }, async (ev) => {
    const attempts = ["machine_credentials", "machine_tokens", "agent_delegations", "principal_audit_log", "firewall_decisions"];
    const results = [];
    for (const table of attempts) {
      const res = await request(w.t.app).put("/firewall/policy").set(as("alice")).send({ database: { tables: { [table]: ["select"] } } });
      results.push({ table, status: res.status, code: res.body?.error?.code });
    }
    ev("attempts", results);
    const allRejected = results.every((r) => r.status === 400);
    return allRejected
      ? defended(`All ${results.length} protected-table policy attempts rejected at the schema level (400).`)
      : notDefended(JSON.stringify(results), "Critical", "PROTECTED_TABLES must cover every table this module keeps, and the policy schema must reject them unconditionally.");
  });

  scenario({
    id: "SA-3",
    category: "Secret access",
    title: "Agent tries to smuggle a real Legion credential through a tool call's arguments",
    attackPath: "A compromised agent that somehow obtained a Legion credential or access token string tries to pass it as an argument to an allowed tool (e.g. embedded in a Slack message or an HTTP request body), for example to relay it out through a channel that isn't directly being watched.",
    expectedDefense: "High-confidence secret-format detection scans tool arguments and blocks the call outright when a Legion credential/token pattern is found, whatever tool is used.",
  }, async (ev) => {
    const a = await mkAgent(w, ["tool.slack:write", "tool.http:write"]);
    const fakeCredential = `lgs_${"a".repeat(32)}_${"B".repeat(43)}`;
    const fakeToken = `lgt_${"C".repeat(43)}`;
    const viaSlack = await authorize(w, a, SLACK("C0SECOPS1", `Rotated credential: ${fakeCredential}`));
    const viaHttpBody = await authorize(w, a, { kind: "http", operation: "request", method: "POST", url: "https://api.partner.example/log", body: JSON.stringify({ token: fakeToken }) });
    ev("viaSlack", brief(viaSlack));
    ev("viaHttpBody", brief(viaHttpBody));
    const bothBlocked = viaSlack.status !== 200 && viaHttpBody.status !== 200;
    return bothBlocked
      ? defended(`Both blocked: ${viaSlack.status} (${viaSlack.body?.error?.rules}), ${viaHttpBody.status} (${viaHttpBody.body?.error?.rules}).`)
      : notDefended(JSON.stringify({ slack: viaSlack.status, http: viaHttpBody.status }), "Critical", "Scan every tool call's arguments/body for Legion credential and token formats.");
  });

  scenario({
    id: "SA-4",
    category: "Secret access",
    title: "Agent tries to pass a secret through an agent-to-agent message payload",
    attackPath: "A compromised agent tries to relay a real Legion credential to a peer agent as the payload of an agent-to-agent request, hoping the peer (with different, perhaps broader, egress permissions) will carry it further.",
    expectedDefense: "The same secret-format scan applies to agent-to-agent payloads; the message is refused before it is ever stored or delivered.",
  }, async (ev) => {
    const sender = await mkAgent(w, ["alerts:read"]);
    const recipient = await mkAgent(w, ["alerts:read"]);
    await setPolicy(w, { agentMessages: { allow: [{ from: sender.agent.id, to: recipient.agent.id }] } });
    const fakeCredential = `lga_${"a".repeat(32)}_${"B".repeat(43)}`;
    const res = await request(w.t.app).post("/agent/v1/messages").set(bearer(sender.token))
      .send({ toAgentId: recipient.agent.id, requestedPermission: "alerts:read", payload: { note: `use this: ${fakeCredential}` } });
    ev("sendWithEmbeddedCredential", { status: res.status, body: res.body });
    const inbox = await request(w.t.app).get("/agent/v1/messages").set(bearer(recipient.token));
    ev("recipientInbox", inbox.body.messages);
    return res.status === 403 && inbox.body.messages.length === 0
      ? defended(`Refused before delivery (${res.body.error?.rules}); recipient's inbox is empty.`)
      : notDefended(JSON.stringify({ sendStatus: res.status, inboxCount: inbox.body.messages.length }), "High", "Scan agent-to-agent payloads for secret formats before storing or delivering the message.");
  });

  scenario({
    id: "SA-5",
    category: "Secret access",
    title: "Agent tries to read sensitive filesystem paths inside its own allowed root",
    attackPath: "An agent granted tool.files:read, confined to a project directory it legitimately works in, creates or finds a .env file, an .ssh directory, or a private key inside that same allowed root — files that happen to be sensitive by nature even though the path itself is within policy.",
    expectedDefense: "Sensitive filename/path patterns (.env, .ssh, id_rsa, *.pem, etc.) are refused even when the path is inside an allowed root.",
  }, async (ev) => {
    const a = await mkAgent(w, ["tool.files:read"]);
    await fs.writeFile(path.join(w.dir, ".env"), "DB_PASSWORD=hunter2\nAPI_KEY=sk-live-abc123").catch(() => {});
    await fs.mkdir(path.join(w.dir, ".ssh"), { recursive: true }).catch(() => {});
    await fs.writeFile(path.join(w.dir, ".ssh", "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END OPENSSH PRIVATE KEY-----").catch(() => {});
    const envRead = await authorize(w, a, { kind: "files", operation: "read", path: path.join(w.dir, ".env") });
    const keyRead = await authorize(w, a, { kind: "files", operation: "read", path: path.join(w.dir, ".ssh", "id_rsa") });
    ev("envRead", brief(envRead));
    ev("sshKeyRead", brief(keyRead));
    const bothBlocked = envRead.status !== 200 && keyRead.status !== 200;
    return bothBlocked
      ? defended(`Both refused: ${envRead.body?.error?.rules}, ${keyRead.body?.error?.rules}.`)
      : notDefended(JSON.stringify({ env: envRead.status, key: keyRead.status }), "High", "Refuse well-known sensitive filenames/paths (.env, .ssh, private keys, credential stores) even inside an allowed root.");
  });

  scenario({
    id: "SA-6",
    category: "Secret access",
    title: "A newly issued credential secret is never retrievable again",
    attackPath: "After creating an agent (which returns the one-time credential secret), an admin fetches the agent's record and the credential list again, checking whether the raw secret value is ever exposed a second time through any read endpoint.",
    expectedDefense: "Only a SHA-256 hash is stored; no endpoint returns the plaintext secret after the initial creation response.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    const getAgent = await request(w.t.app).get(`/agents/${a.agent.id}`).set(as("alice"));
    const listCredentials = await request(w.t.app).get(`/agents/${a.agent.id}/credentials`).set(as("alice"));
    const dump = JSON.stringify({ getAgent: getAgent.body, listCredentials: listCredentials.body });
    ev("getAgentBody", getAgent.body);
    ev("listCredentialsBody", listCredentials.body);
    const leaked = dump.includes(a.secret);
    return !leaked
      ? defended("The raw credential secret does not appear in any subsequent read response.")
      : notDefended("The raw secret value was found in a later API response.", "Critical", "Never return the plaintext credential secret after the initial creation response; store and compare only its hash.");
  });
});
