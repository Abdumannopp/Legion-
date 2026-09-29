import { describe, expect, it } from "vitest";
import { assess, isUnsafeAction } from "../src/behavior/assess.js";
import { destinationKey } from "../src/behavior/keys.js";
import { levelOf, type BehaviorProfile, type WindowEvent } from "../src/behavior/types.js";

const NOW = new Date("2026-09-26T12:00:00Z");
const START = new Date(NOW.getTime() - 60 * 60_000);

/** A triage agent: reads alerts, comments, posts to one Slack channel, around the clock. */
function profile(over: Partial<BehaviorProfile> = {}): BehaviorProfile {
  return {
    events: 500, since: "2026-09-12T00:00:00Z", until: START.toISOString(),
    hourly: { mean: 2, std: 1, p95: 4, activeHours: 250 },
    actions: { "alerts:read": 300, "alerts:comment": 100, "tool:slack.post_message": 100 },
    resourceTypes: { alert: 400, "tool:slack": 100 },
    destinations: { "api:alert": 400, "slack:C0SECOPS1": 100 },
    externalDestinations: { "slack:C0SECOPS1": 100 },
    peers: { "agent:peer-1": 5 },
    delegatedUsers: { anna: 20 },
    blockRate: 0.02, sensitiveRate: 0.05, messagesPerHour: 0.2,
    hoursOfDay: Array.from({ length: 24 }, (_, h) => (h >= 22 || h < 4 ? 0 : 20)),
    established: true,
    ...over,
  };
}

function ev(over: Partial<WindowEvent> = {}, minutesAgo = 5): WindowEvent {
  return {
    occurredAt: new Date(NOW.getTime() - minutesAgo * 60_000).toISOString(),
    surface: "api", action: "alerts:read", resourceType: "alert", destination: "api:alert",
    sensitivity: "internal", decision: "ALLOW", ruleIds: [], delegatedUser: null, viaMessage: false, ...over,
  };
}
const many = (n: number, over: Partial<WindowEvent> = {}) => Array.from({ length: n }, (_, i) => ev(over, (i % 50) + 1));
const run = (events: WindowEvent[], p = profile(), extra: { failures?: number; content?: { malicious: number; suspicious: number } } = {}) =>
  assess({ profile: p, events, windowStart: START, windowEnd: NOW, failures: extra.failures ?? 0, content: extra.content });
const ids = (a: ReturnType<typeof run>) => a.signals.map((s) => s.id);

describe("normal work is NORMAL", () => {
  it("the agent's usual mix at its usual rate", () => {
    const a = run([...many(2), ev({ action: "alerts:comment" }), ev({ action: "tool:slack.post_message", resourceType: "tool:slack", destination: "slack:C0SECOPS1", surface: "tool_call" })]);
    expect(a).toMatchObject({ level: "NORMAL", score: 0, signals: [] });
  });
  it("a quiet window", () => {
    expect(run([]).level).toBe("NORMAL");
  });
});

describe("each monitored dimension", () => {
  it("request volume: a spike, and an extreme spike", () => {
    expect(ids(run(many(40)))).toEqual(["volume.spike"]);
    expect(ids(run(many(200)))).toEqual(["volume.extreme"]);
  });

  it("tool usage: new actions, and new unsafe tools weigh more", () => {
    expect(ids(run([ev({ action: "assets:read", resourceType: "alert" })]))).toContain("tools.new");
    const a = run([ev({ action: "tool:shell.execute", surface: "tool_call", destination: "shell:git", resourceType: "tool:shell" })]);
    expect(a.signals.find((s) => s.id === "tools.new_unsafe")).toMatchObject({ points: 25, evidence: ["tool:shell.execute"] });
  });

  it("accessed resources: new kinds of resource", () => {
    expect(ids(run([ev({ resourceType: "asset" })]))).toContain("resources.new_types");
  });

  it("external destinations: one new, several new, and fan-out", () => {
    const post = (host: string) => ev({ action: "tool:slack.post_message", surface: "tool_call", resourceType: "tool:slack", destination: `slack:${host}` });
    expect(ids(run([post("C0NEW0001")]))).toContain("destinations.new");
    expect(ids(run(["A", "B", "C"].map((h) => post(`C0NEW000${h}`))))).toContain("destinations.many_new");
    const fan = Array.from({ length: 12 }, (_, i) => ev({ action: "egress:request", surface: "egress", destination: `url:https://h${i}.example.net/x` }));
    expect(run(fan).signals.find((s) => s.id === "destinations.fan_out")?.points).toBe(40);
  });

  it("a new path on a known host is not a new destination", () => {
    const p = profile({ externalDestinations: { "url:api.partner.com": 50 }, destinations: { "url:api.partner.com": 50 }, actions: { "egress:request": 50 } });
    expect(run([ev({ action: "egress:request", surface: "egress", destination: "url:https://api.partner.com/v2/other" })], p).signals).toEqual([]);
  });

  it("failed operations: block rate, mostly blocked, probing, errors", () => {
    const blocked = (rule: string) => ev({ decision: "BLOCK", ruleIds: [rule] });
    expect(ids(run([...many(7), ...["x.a", "x.b", "x.c"].map(blocked)]))).toContain("failures.block_rate");
    expect(ids(run([...many(3), ...Array.from({ length: 9 }, () => blocked("permission.not_granted"))]))).toContain("failures.mostly_blocked");
    expect(ids(run(["a.1", "b.2", "c.3", "d.4"].map(blocked)))).toContain("failures.probing");
    expect(ids(run(many(30), profile(), { failures: 20 }))).toContain("failures.errors");
  });

  it("behaviour-rule blocks do not feed back into the failure signals", () => {
    const self = Array.from({ length: 12 }, () => ev({ decision: "BLOCK", ruleIds: ["behavior.critical_containment"] }));
    expect(ids(run(self))).not.toContain("failures.mostly_blocked");
  });

  it("sensitive data: restricted attempts, and a rise in confidential access", () => {
    expect(ids(run([ev({ sensitivity: "restricted", decision: "BLOCK", ruleIds: ["sensitivity.restricted"] })]))).toContain("sensitive.restricted_attempt");
    expect(ids(run(many(12, { sensitivity: "confidential" })))).toContain("sensitive.increase");
  });

  it("agent-to-agent: new peers, bursts, and blocks while acting for another agent", () => {
    const msg = (peer: string) => ev({ action: "agents:message", surface: "agent_message", destination: `agent:${peer}` });
    expect(ids(run([msg("peer-2")]))).toContain("a2a.new_peers");
    expect(ids(run(Array.from({ length: 12 }, () => msg("peer-1"))))).toContain("a2a.burst");
    expect(ids(run(Array.from({ length: 3 }, () => ev({ viaMessage: true, decision: "BLOCK", ruleIds: ["a2a.message_scope"] })))))
      .toContain("a2a.blocked_on_behalf");
  });

  it("changes in timing: activity at hours the agent is never active", () => {
    const night = new Date("2026-09-26T02:30:00Z");
    const events = Array.from({ length: 6 }, (_, i) => ({ ...ev(), occurredAt: new Date(night.getTime() + i * 60_000).toISOString() }));
    expect(ids(assess({ profile: profile(), events, windowStart: new Date(night.getTime() - 3_600_000), windowEnd: new Date(night.getTime() + 600_000), failures: 0 })))
      .toContain("timing.unusual_hours");
  });

  it("delegation: acting for people it never acted for", () => {
    expect(ids(run([ev({ delegatedUser: "mallory" })]))).toContain("delegation.new_users");
  });

  it("external content: malicious content that reached the agent", () => {
    expect(ids(run([], profile(), { content: { malicious: 1, suspicious: 0 } }))).toContain("content.malicious");
  });
});

describe("classification", () => {
  it("thresholds", () => {
    expect([0, 29, 30, 59, 60, 84, 85, 100].map(levelOf)).toEqual(
      ["NORMAL", "NORMAL", "SUSPICIOUS", "SUSPICIOUS", "HIGH_RISK", "HIGH_RISK", "CRITICAL", "CRITICAL"]);
  });

  it("one noisy dimension alone is at most SUSPICIOUS/HIGH_RISK, never CRITICAL", () => {
    expect(run(many(500)).level).toBe("SUSPICIOUS"); // extreme volume alone: 35
    const fan = Array.from({ length: 30 }, (_, i) => ev({ action: "alerts:read", destination: `url:https://h${i}.example.net/` }));
    expect(run(fan).level).toBe("SUSPICIOUS"); // fan-out alone: 40
  });

  it("an exfiltration pattern — new outbound tool, fan-out, volume — is CRITICAL", () => {
    const events = Array.from({ length: 120 }, (_, i) => ev({ action: "tool:http.post", surface: "tool_call", destination: `url:https://drop${i % 15}.example.net/u`, resourceType: "tool:http" }));
    const a = run(events);
    expect(a.level).toBe("CRITICAL");
    expect(ids(a)).toEqual(expect.arrayContaining(["tools.new_unsafe", "destinations.fan_out", "volume.extreme"]));
  });

  it("boundary probing with attack indicators is CRITICAL", () => {
    const rules = ["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"];
    const a = run([...many(2), ...Array.from({ length: 12 }, (_, i) => ev({ decision: "BLOCK", ruleIds: [rules[i % 4]!] }))]);
    expect(a.level).toBe("CRITICAL");
    expect(a.signals.find((s) => s.id === "attack.indicators")?.evidence).toEqual(expect.arrayContaining(rules));
  });
});

describe("without a baseline", () => {
  const fresh = profile({ established: false, events: 3, actions: {}, destinations: {}, externalDestinations: {}, resourceTypes: {}, peers: {}, delegatedUsers: {} });

  it("new things are not anomalies — a new agent is new at everything", () => {
    const a = run([ev({ action: "tool:slack.post_message", destination: "slack:C0X" }), ev({ action: "tool:shell.execute" })], fresh);
    expect(a.signals).toEqual([]);
    expect(a.level).toBe("NORMAL");
  });

  it("broad deviation without intent is capped at SUSPICIOUS", () => {
    const events = Array.from({ length: 700 }, (_, i) => ev({ action: "egress:request", destination: `url:https://h${i % 20}.example.net/` }));
    const a = run(events, fresh);
    expect(a.score).toBeLessThanOrEqual(59);
  });

  it("intent evidence still counts in full", () => {
    const rules = ["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"];
    const a = run(Array.from({ length: 12 }, (_, i) => ev({ decision: "BLOCK", ruleIds: [rules[i % 4]!] })), fresh);
    expect(a.level).toBe("CRITICAL");
  });
});

describe("helpers", () => {
  it("unsafe = changes state or leaves Legion; reads are safe", () => {
    expect(["tool:shell.execute", "tool:http.post", "tool:slack.post_message", "tool:cloud.ec2:TerminateInstances", "egress:request", "agents:message", "tool:github.push_commit"].every(isUnsafeAction)).toBe(true);
    expect(["tool:database.select", "tool:http.get", "tool:files.read", "tool:cloud.ec2:DescribeInstances", "tool:github.read_issue", "tool:browser.navigate", "alerts:read", "alerts:update_status"].some(isUnsafeAction)).toBe(false);
  });
  it("destination keys compare hosts, directories, and sorted domain sets", () => {
    expect(destinationKey("url:https://API.partner.com:443/v1?x=1")).toBe("url:api.partner.com");
    expect(destinationKey("file:/srv/work/reports/q3.csv")).toBe("file:/srv/work/reports");
    expect(destinationKey("email:b.com,a.com")).toBe("email:a.com,b.com");
  });
});
