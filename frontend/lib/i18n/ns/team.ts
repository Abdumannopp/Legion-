import { defineMessages } from "../core";

/**
 * Legion's five agents and the skills each one has. The skill lines are keyed
 * by skill name (server: packages/agent-identity/src/skills/builtin); a skill
 * without a line here falls back to the server's own English description.
 */
export const team = defineMessages({
  en: {
    title: "Legion team",
    intro: "Five agents, each with one job. Their skills are tools you can give to your own AI agents (open an agent → Skills), so they check your security the same way Legion does. Legion's own detection and blocking run by themselves — see Defense.",
    skills: (n: number) => (n === 1 ? "1 skill" : `${n} skills`),
    onlyRecommends: "Skills only read your data and recommend. Nothing here blocks, deletes or changes anything — a person approves and does that.",
    loadFailed: "Could not load the skills.",
    assign: {
      intro: "Choose which skills this agent may use. A skill only reads and recommends. The agent also needs the permissions the skill reads with — nothing is granted by choosing a skill.",
      use: "Use this skill",
      needs: (list: string) => `Also needs permission: ${list}. Grant it in “What it can do”.`,
      ready: "Ready to use",
      saved: "Saved",
      adminOnly: "Only workspace admins can choose an agent's skills.",
    },
    agents: {
      Sentinel: { role: "Watches", job: "Keeps an eye on sign-ins, accounts and events from your servers, and notices when something is wrong." },
      Hunter: { role: "Hunts", job: "Connects separate events into one attack, and looks for data being gathered and sent out." },
      Guardian: { role: "Protects", job: "Finds what is open to attack before anyone attacks it, and checks Legion's own defences." },
      Oracle: { role: "Explains and prioritises", job: "Explains what an alert means in plain words and puts the open alerts in the order to handle them." },
      Executor: { role: "Prepares the response", job: "Prepares what to do next — which address to block, what to isolate — with the evidence, for a person to approve." },
    } as Record<string, { role: string; job: string }>,
    skillLines: {
      threat_detection: "Finds suspicious patterns in recent events and groups the related ones.",
      account_activity_watch: "Spots stolen or guessed accounts: a login after many failures, one account used from many addresses, one address trying many accounts.",
      attack_investigation: "Links related events into one attack timeline.",
      threat_intelligence: "Checks addresses, domains and files against known threats.",
      data_exfiltration_hunt: "Finds data being gathered and then sent out: a database dump followed by an upload.",
      vulnerability_analysis: "Explains known weaknesses on your assets and how to fix them.",
      ai_security_red_team: "Tests Legion's own defences with safe, synthetic attacks.",
      exposure_review: "Ranks assets by how likely they are to be attacked: reachable from the internet, with known weaknesses.",
      threat_coverage: "Shows, for the seven most dangerous attack types, what Legion detected, what it watches and where it is blind.",
      payment_fraud_review: "Reviews held payments: what waits for a phone confirmation, and patterns that look like fraud.",
      alert_analysis: "Explains one alert: what happened, to what, and what to check next.",
      security_reporting: "Writes a security report with evidence and recommended next steps.",
      triage_priority: "Orders the open alerts: what needs attention now, today, this week — and why.",
      incident_response: "Builds a response plan: containment, investigation and recovery steps.",
      containment_candidates: "Lists the attacking addresses worth blocking, and the ones that must not be blocked.",
      secret_exposure_check: "Finds passwords, keys, card numbers and bank account numbers that ended up in logs. Shows the kind and where, never the value.",
      sensitive_access_watch: "Watches who opens customer records, payroll, contracts, keys and backups, and flags an account that opens too many.",
      response_sla_review: "Measures open alerts against response targets and lists the late ones: your answer to \"how fast do you respond?\".",
    } as Record<string, string>,
  },
});
