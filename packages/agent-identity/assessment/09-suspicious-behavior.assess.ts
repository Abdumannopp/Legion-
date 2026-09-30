/*
 * Category: Suspicious behavior — an agent's live activity is compared with
 * its own learned baseline, and enforcement is risk-based rather than
 * block-everything. Each scenario establishes a realistic baseline (via the
 * decision log, a legitimate test input) and then performs the anomalous
 * activity live, against the running route.
 */
import request from "supertest";
import { describe } from "vitest";
import { as, bearer } from "../test/helpers.js";
import { authorize, establishNormalBaseline, HTTP_CALL, mkAgent, SLACK, useWorld, authorizeApproved } from "./setup.js";
import { defended, notDefended, partial, scenario } from "./harness.js";

const w = useWorld();
const postSlack = (token: string, channel: string) =>
  request(w.t.app).post("/agent/v1/tools/authorize").set(bearer(token)).send({ call: { kind: "slack", operation: "post_message", channel, text: "message" } });

describe("Suspicious behavior", () => {
  scenario({
    id: "SB-1",
    category: "Suspicious behavior",
    title: "Volume alone: a moderate burst is deliberately not enough by itself, but an extreme one is caught",
    attackPath: "An agent with five days of steady, low-volume history (~1.4 actions/hour) suddenly issues a large burst of requests — first a moderate one (~40x its normal rate), then a much larger one (~150x), simulating a script now driving the agent.",
    expectedDefense: "By design (confirmed against the module's own unit tests), a single moderate-volume signal alone stays below the SUSPICIOUS threshold to avoid false positives on ordinary bursts of work; a genuinely extreme spike (3x the agent's already-generous ceiling) does cross it. This scenario verifies both halves of that design live, rather than assuming either one.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read", "tool.slack:write"]);
    await establishNormalBaseline(w, a.agent);
    for (let i = 0; i < 60; i++) await request(w.t.app).get("/agent/v1/alerts").set(bearer(a.token));
    const moderateBurst = await request(w.t.app).get(`/behavior/agents/${a.agent.id}`).set(as("anna"));
    ev("moderateBurst_60req", { level: moderateBurst.body.assessment?.level, score: moderateBurst.body.assessment?.score, signals: moderateBurst.body.assessment?.signals?.map((s: { id: string }) => s.id) });

    for (let i = 0; i < 180; i++) await request(w.t.app).get("/agent/v1/alerts").set(bearer(a.token));
    const extremeBurst = await request(w.t.app).get(`/behavior/agents/${a.agent.id}`).set(as("anna"));
    ev("extremeBurst_240reqTotal", { level: extremeBurst.body.assessment?.level, score: extremeBurst.body.assessment?.score, signals: extremeBurst.body.assessment?.signals?.map((s: { id: string }) => s.id) });

    const moderateStayedLow = moderateBurst.body.assessment?.level === "NORMAL";
    const extremeCaught = extremeBurst.body.assessment?.level !== "NORMAL" && extremeBurst.body.assessment?.signals?.some((s: { id: string }) => s.id === "volume.extreme");
    if (moderateStayedLow && extremeCaught) {
      return defended(`Moderate burst (60 req, "volume.spike", score ${moderateBurst.body.assessment.score}) stayed NORMAL as designed; extreme burst reached ${extremeBurst.body.assessment.level} via volume.extreme (score ${extremeBurst.body.assessment.score}).`);
    }
    return extremeCaught
      ? partial("Extreme volume is caught, but the moderate-burst threshold behaves differently than the module's own tests document.", "Low", "Re-check normalMax/threshold constants against behavior-assess.test.ts.")
      : notDefended(`extremeBurstLevel=${extremeBurst.body.assessment?.level}`, "Medium", "A genuinely extreme request-volume spike (3x the ceiling) must raise the behaviour level.");
  });

  scenario({
    id: "SB-2",
    category: "Suspicious behavior",
    title: "New unsafe tool + volume reaches HIGH_RISK; the specific containment rule has a documented ~30s cache lag, covered meanwhile by generic risk scoring",
    attackPath: "An agent with an established read/Slack-only habit suddenly (a) generates extreme volume and (b) uses a brand-new, external-effect tool family (HTTP) it has never touched — the exfiltration-shaped pattern the module's own design targets. This checks not just whether the level rises, but exactly *when*, within a single fast-moving attack, the specific behaviour-containment hard rule (behavior.high_risk_novel_action) actually engages for live enforcement, versus the module's documented per-instance cache lag (behaviorRefreshSeconds, default 30s) for that specific rule.",
    expectedDefense: "GET /behavior/agents/:id (which always refreshes) correctly reports HIGH_RISK immediately. For live enforcement within the same ~30s cache window as the still-cached prior (NORMAL) state, the specific behavior.* hard rule may not yet be the one that blocks a given call — but this is not a live-enforcement gap: generic tool risk-scoring (permission tier, external effect, sensitivity) independently blocks the same risky new action in this case. After the cache refreshes (forced here the same way a periodic sweep would), the specific behavior.high_risk_novel_action hard rule fires directly on a subsequent similar attempt, and the agent's established, non-novel action keeps working throughout.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read", "tool.slack:write", "tool.http:write"]);
    await establishNormalBaseline(w, a.agent);
    for (let i = 0; i < 100; i++) await request(w.t.app).get("/agent/v1/alerts").set(bearer(a.token));

    // Within the same cache window as the (still-NORMAL) state cached by the reads above.
    const newToolWithinCacheWindow = await authorize(w, a, HTTP_CALL("https://api.partner.example/upload-1", "POST", "data"));
    ev("newTool_withinCacheWindow", { status: newToolWithinCacheWindow.status, blockedBy: newToolWithinCacheWindow.body?.error?.rules ?? newToolWithinCacheWindow.body?.rules?.map((r: { id: string }) => r.id) });

    // Forces a fresh assessment (exactly what /behavior/agents/:id, and a periodic sweep, do).
    const freshAssessment = await request(w.t.app).get(`/behavior/agents/${a.agent.id}`).set(as("anna"));
    ev("freshAssessmentAfterExplicitRefresh", { level: freshAssessment.body.assessment?.level, score: freshAssessment.body.assessment?.score, signals: freshAssessment.body.assessment?.signals?.map((s: { id: string }) => s.id) });

    // Same kind of attempt again, now that the cache is fresh and correctly reflects HIGH_RISK.
    const newToolAfterRefresh = await authorize(w, a, HTTP_CALL("https://api.partner.example/upload-2", "POST", "data"));
    ev("newTool_afterRefresh", { status: newToolAfterRefresh.status, blockedBy: newToolAfterRefresh.body?.error?.rules ?? newToolAfterRefresh.body?.rules?.map((r: { id: string }) => r.id) });

    const establishedStillWorks = await authorizeApproved(w, a, SLACK("C0SECOPS1"));
    ev("establishedChannelStillWorks", { status: establishedStillWorks.status, decision: establishedStillWorks.body?.decision });

    const level = freshAssessment.body.assessment?.level;
    const cacheWindowRulesArr: string[] = newToolWithinCacheWindow.body?.error?.rules ?? [];
    const specificRuleFiredAfterRefresh: string[] = newToolAfterRefresh.body?.error?.rules ?? [];
    const blockedThroughout = newToolWithinCacheWindow.status !== 200 && newToolAfterRefresh.status !== 200;
    const specificRuleEventuallyFired = specificRuleFiredAfterRefresh.includes("behavior.high_risk_novel_action") || specificRuleFiredAfterRefresh.includes("behavior.critical_containment");
    const establishedOk = establishedStillWorks.status === 200;

    if ((level === "HIGH_RISK" || level === "CRITICAL") && blockedThroughout && specificRuleEventuallyFired && establishedOk) {
      return defended(
        `Level correctly reported ${level}. Within the pre-refresh cache window the new-tool attempt was still blocked, but by generic risk scoring (${cacheWindowRulesArr.join(", ") || "none listed"}), not yet by the behavior-specific rule — matching the documented ~30s cache lag. After an explicit refresh, the same kind of attempt was blocked directly by ${specificRuleFiredAfterRefresh.join(", ")}. The agent's established, non-novel action kept working throughout.`,
      );
    }
    return level === "HIGH_RISK" || level === "CRITICAL"
      ? partial(
          `Level reached ${level} but the outcome pattern differed from expectations: blockedThroughout=${blockedThroughout}, specificRuleEventuallyFired=${specificRuleEventuallyFired}, establishedOk=${establishedOk}.`,
          "Medium",
          "Re-verify the cache-lag behaviour and confirm generic risk scoring reliably covers the gap for every action type, not only tool.http:write-shaped ones.",
        )
      : notDefended(`level never reached HIGH_RISK/CRITICAL (got ${level})`, "Medium", "Extreme volume + a brand-new external-effect tool should reliably reach HIGH_RISK.");
  });

  scenario({
    id: "SB-3",
    category: "Suspicious behavior",
    title: "A brand-new agent's first activity is not itself treated as an attack",
    attackPath: "A freshly created agent, with no history at all, immediately does a variety of different things (it's new — everything is 'new' for it). This checks the monitor does not cry wolf on legitimate day-one activity, which would make the signal useless in practice.",
    expectedDefense: "Without an established baseline, ordinary variety in a new agent's first actions is NOT classified as suspicious purely for being 'new' (no intent evidence).",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read", "tool.slack:write"]);
    await request(w.t.app).get("/agent/v1/alerts").set(bearer(a.token));
    await postSlack(a.token, "C0SECOPS1");
    const assessment = await request(w.t.app).get(`/behavior/agents/${a.agent.id}`).set(as("anna"));
    ev("assessment", { level: assessment.body.assessment?.level, established: assessment.body.profile?.established });
    return assessment.body.assessment?.level === "NORMAL"
      ? defended("A new agent's ordinary first activity stayed NORMAL.")
      : partial(`level=${assessment.body.assessment?.level} for a brand-new agent's ordinary first actions.`, "Low", "Ensure new agents aren't penalized purely for lacking history; only concrete intent evidence (probing, attack indicators) should raise risk before a baseline exists.");
  });
});
