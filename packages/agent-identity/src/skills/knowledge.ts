import net from "node:net";
import { CVE_RE, type IndicatorType, type SecurityEvent } from "./types.js";

/*
 * Deterministic security knowledge the skills share: attack stages, what
 * event text means, and how to pull indicators out of it. Nothing here does
 * I/O or asks a model — every conclusion a skill draws can be traced to a
 * rule in this file and a field in the event.
 */

/**
 * Attack stages in the order an intrusion usually unfolds. Based on MITRE
 * ATT&CK tactics; credential attacks on a login are placed before initial
 * access because that is the order they appear in on a single host
 * (failed logins, then the successful one).
 */
export const STAGES = [
  "reconnaissance",
  "credential_access",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "discovery",
  "lateral_movement",
  "command_and_control",
  "exfiltration",
  "impact",
] as const;
export type Stage = (typeof STAGES)[number];
export const STAGE_ORDER: Record<Stage, number> = Object.fromEntries(STAGES.map((s, i) => [s, i])) as Record<Stage, number>;

/** MITRE ATT&CK techniques Legion recognises, with the stage and a plain name. */
export const TECHNIQUES: Record<string, { stage: Stage; name: string; points: number }> = {
  T1595: { stage: "reconnaissance", name: "Active scanning", points: 5 },
  T1046: { stage: "discovery", name: "Network service discovery", points: 10 },
  T1087: { stage: "discovery", name: "Account discovery", points: 10 },
  T1110: { stage: "credential_access", name: "Brute force", points: 15 },
  T1003: { stage: "credential_access", name: "OS credential dumping", points: 30 },
  T1078: { stage: "initial_access", name: "Valid accounts", points: 15 },
  T1190: { stage: "initial_access", name: "Exploit public-facing application", points: 25 },
  T1566: { stage: "initial_access", name: "Phishing", points: 15 },
  T1059: { stage: "execution", name: "Command and scripting interpreter", points: 20 },
  T1204: { stage: "execution", name: "User execution", points: 15 },
  T1053: { stage: "persistence", name: "Scheduled task/job", points: 15 },
  T1136: { stage: "persistence", name: "Create account", points: 20 },
  T1098: { stage: "persistence", name: "Account manipulation", points: 20 },
  T1543: { stage: "persistence", name: "Create or modify system process", points: 20 },
  T1547: { stage: "persistence", name: "Boot or logon autostart execution", points: 20 },
  T1068: { stage: "privilege_escalation", name: "Exploitation for privilege escalation", points: 25 },
  T1548: { stage: "privilege_escalation", name: "Abuse elevation control mechanism", points: 20 },
  T1055: { stage: "defense_evasion", name: "Process injection", points: 25 },
  T1070: { stage: "defense_evasion", name: "Indicator removal", points: 25 },
  T1562: { stage: "defense_evasion", name: "Impair defenses", points: 30 },
  T1021: { stage: "lateral_movement", name: "Remote services", points: 20 },
  T1071: { stage: "command_and_control", name: "Application layer protocol", points: 20 },
  T1105: { stage: "command_and_control", name: "Ingress tool transfer", points: 20 },
  T1041: { stage: "exfiltration", name: "Exfiltration over C2 channel", points: 30 },
  T1048: { stage: "exfiltration", name: "Exfiltration over alternative protocol", points: 30 },
  T1485: { stage: "impact", name: "Data destruction", points: 35 },
  T1486: { stage: "impact", name: "Data encrypted for impact", points: 40 },
  T1490: { stage: "impact", name: "Inhibit system recovery", points: 35 },
  T1565: { stage: "impact", name: "Data manipulation", points: 25 },
};

/** Patterns in event titles/summaries (Wazuh rule descriptions and logs). */
export const SIGNALS: { id: string; stage: Stage; label: string; points: number; re: RegExp }[] = [
  { id: "failed_authentication", stage: "credential_access", label: "Failed authentication", points: 10,
    re: /\b(?:authentication fail(?:ed|ure)|failed password|invalid user|login fail(?:ed|ure)|failed login|logon failure|multiple failed|brute[- ]?force)\b/i },
  { id: "successful_login", stage: "initial_access", label: "Successful login", points: 5,
    re: /\b(?:accepted (?:password|publickey|keyboard-interactive)|successful(?:ly)? (?:login|logon|log(?:ged)? in|authenticat\w*)|login success\w*|session opened|logged in)\b/i },
  { id: "privilege_use", stage: "privilege_escalation", label: "Privilege use or escalation", points: 15,
    re: /\b(?:sudo|su\[|privilege[sd]? (?:escalat\w+|elevat\w+)|added to (?:the )?(?:admin\w*|sudo|wheel) group|uid=0\b)/i },
  { id: "account_created", stage: "persistence", label: "Account created or changed", points: 15,
    re: /\b(?:new user|user (?:added|created)|useradd|account (?:was )?created|password changed for)\b/i },
  { id: "suspicious_process", stage: "execution", label: "Unusual process or command", points: 15,
    re: /\b(?:(?:unusual|suspicious|unexpected|new) process|process (?:started|created|executed)|executed command|powershell|cmd\.exe|\/bin\/(?:ba)?sh\b|bash -i|reverse shell|netcat|\bnc -e)\b/i },
  { id: "obfuscated_command", stage: "execution", label: "Obfuscated or encoded command", points: 15,
    re: /(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{16,}|frombase64string|base64 -d)/i },
  { id: "network_connection", stage: "command_and_control", label: "Unusual network connection", points: 10,
    re: /\b(?:outbound connection|network connection|connection (?:to|from) (?:an? )?(?:unusual|suspicious|external|unknown)|beacon\w*|command[- ]and[- ]control|\bc2\b|dns tunnel\w*)\b/i },
  { id: "file_modification", stage: "impact", label: "File modified, added or deleted", points: 10,
    re: /\b(?:integrity checksum changed|file (?:was )?(?:modified|changed|added|deleted|created)|syscheck)\b/i },
  { id: "ransomware", stage: "impact", label: "Ransomware behaviour", points: 40,
    re: /\b(?:ransom\w*|files? encrypted|shadow cop(?:y|ies) deleted|vssadmin(?:\.exe)? delete)\b/i },
  { id: "malware", stage: "execution", label: "Malware detected", points: 30,
    re: /\b(?:malware|trojan|virus|rootkit|backdoor|cryptominer|webshell)\b/i },
  { id: "scanning", stage: "reconnaissance", label: "Scanning", points: 5,
    re: /\b(?:port ?scan\w*|nmap|network scan\w*|vulnerability scan\w*)\b/i },
  { id: "exfiltration", stage: "exfiltration", label: "Possible data exfiltration", points: 30,
    re: /\b(?:exfiltrat\w+|large (?:upload|outbound transfer)|data transfer to)\b/i },
  { id: "defense_evasion", stage: "defense_evasion", label: "Logging or defences tampered with", points: 30,
    re: /\b(?:(?:audit|event|security) log (?:was )?cleared|log(?:s)? (?:deleted|cleared)|auditd (?:stopped|disabled)|(?:firewall|antivirus|defender|edr|av) (?:was )?(?:disabled|stopped|turned off))\b/i },
  { id: "web_attack", stage: "initial_access", label: "Web attack or exploit attempt", points: 20,
    re: /\b(?:sql injection|\bxss\b|cross[- ]site scripting|web attack|remote code execution|\brce\b|exploit\w*|path traversal|command injection)\b/i },
  { id: "lateral_movement", stage: "lateral_movement", label: "Lateral movement", points: 20,
    re: /\b(?:lateral movement|psexec|wmiexec|remote desktop|\brdp\b login|pass[- ]the[- ](?:hash|ticket))\b/i },
];

export interface EventReading {
  signals: { id: string; label: string; stage: Stage; points: number }[];
  techniques: { id: string; name: string; stage: Stage; points: number }[];
  /** Earliest-applicable stage is not meaningful; this is the most specific one found, or null. */
  stages: Stage[];
}

/** What an event's fields and text say, by rule. */
export function readEvent(e: SecurityEvent): EventReading {
  const text = `${e.title}\n${e.summary}\n${e.process ?? ""}\n${e.filePath ?? ""}`;
  const signals = SIGNALS.filter((s) => s.re.test(text)).map(({ id, label, stage, points }) => ({ id, label, stage, points }));
  const techniques = e.mitreTechniques
    .map((t) => ({ id: t, known: TECHNIQUES[t.split(".")[0]!] }))
    .filter((t) => t.known)
    .map((t) => ({ id: t.id, name: t.known!.name, stage: t.known!.stage, points: t.known!.points }));
  const stages = [...new Set([...techniques.map((t) => t.stage), ...signals.map((s) => s.stage)])];
  return { signals, techniques, stages };
}

/**
 * The single stage used to place an event in an attack chain. MITRE ids
 * (set by the sensor) outrank text patterns; among several, the latest
 * stage wins, since an event usually reports how far an attack has got.
 */
export function primaryStage(r: EventReading): Stage | null {
  const pick = (list: Stage[]) => list.sort((a, b) => STAGE_ORDER[b] - STAGE_ORDER[a])[0] ?? null;
  return pick(r.techniques.map((t) => t.stage)) ?? pick(r.signals.map((s) => s.stage));
}

export const SEVERITY_POINTS = { low: 10, medium: 25, high: 45, critical: 65 } as const;

export function levelOf(score: number): "low" | "medium" | "high" | "critical" {
  return score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
}

// ---- Attack types and playbooks -------------------------------------------------

export const ATTACK_TYPES: Record<Stage, string> = {
  reconnaissance: "Reconnaissance / scanning",
  credential_access: "Credential attack (e.g. brute force, credential dumping)",
  initial_access: "Initial access (login with valid credentials, exploit, phishing)",
  execution: "Malicious execution (process, script or malware)",
  persistence: "Persistence (new account, service, scheduled task)",
  privilege_escalation: "Privilege escalation",
  defense_evasion: "Defence evasion (logs cleared, defences disabled)",
  discovery: "Discovery (enumerating hosts, accounts or services)",
  lateral_movement: "Lateral movement",
  command_and_control: "Command and control / unusual network connection",
  exfiltration: "Data exfiltration",
  impact: "Impact (files modified, encrypted or destroyed)",
};

export const INVESTIGATION_STEPS: Record<Stage, string[]> = {
  reconnaissance: [
    "Identify the scanning source and whether it is internal (an authorised scanner) or external.",
    "Check which services on the target answered and whether any of them are unexpectedly exposed.",
  ],
  credential_access: [
    "Count failed attempts per account and source address over the last 24 hours.",
    "Check whether any attempt from the same source later succeeded.",
    "Confirm whether the targeted accounts exist and are privileged.",
  ],
  initial_access: [
    "Verify with the account owner that the login was theirs (time, location, device).",
    "Review what the session did after login (commands, processes, files).",
    "Check for earlier failed attempts from the same source.",
  ],
  execution: [
    "Collect the full command line, parent process and user of the process.",
    "Check the executable's hash against threat intelligence.",
    "Look for network connections and file changes made by the process.",
  ],
  persistence: [
    "List accounts, services, scheduled tasks and autostart entries created around the event time.",
    "Confirm each with its owner or change ticket.",
  ],
  privilege_escalation: [
    "Identify which account gained privileges and how (sudo rule, group change, exploit).",
    "Check whether the elevation was expected and what was done with it.",
  ],
  defense_evasion: [
    "Establish what logging or protection was changed, by whom, and restore it.",
    "Treat the gap in logs as a period of unknown activity and review other sources for it.",
  ],
  discovery: [
    "Identify the account and host performing enumeration and whether that is part of its normal role.",
  ],
  lateral_movement: [
    "Map which hosts the source account connected to and when.",
    "Check each destination host for the same indicators.",
  ],
  command_and_control: [
    "Identify the process that opened the connection and the destination's reputation.",
    "Check how long and how often the host has talked to that destination (beaconing).",
  ],
  exfiltration: [
    "Estimate the volume and destination of data transferred.",
    "Identify which data stores the source host or account can read.",
  ],
  impact: [
    "Identify which files changed, when, and by which process or account.",
    "Check backups for the affected data and whether they are intact.",
  ],
};

// ---- Indicators -----------------------------------------------------------------------

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IPV6_RE = /(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi;
const URL_RE = /\bhttps?:\/\/[^\s"'<>()\]]+/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b/g;
const DOMAIN_RE = /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b/g;
const HASH_RE = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
const CVE_TEXT_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

/** File extensions that look like TLDs in log text; "config.json" is not a domain. */
const NOT_A_TLD = new Set([
  "txt", "log", "exe", "dll", "sh", "py", "js", "ts", "json", "conf", "cfg", "ini", "php", "html", "htm", "xml", "yml", "yaml",
  "bak", "tmp", "zip", "gz", "tar", "so", "jar", "ps1", "bat", "cmd", "db", "sql", "csv", "pdf", "doc", "docx", "xls", "xlsx",
  "png", "jpg", "jpeg", "gif", "service", "socket", "pid", "lock", "old", "swp", "id", "description", "level", "name",
]);

export interface Indicator {
  type: IndicatorType;
  value: string;
}

export function hashKind(v: string): "md5" | "sha1" | "sha256" | null {
  if (!/^[a-f0-9]+$/i.test(v)) return null;
  return v.length === 32 ? "md5" : v.length === 40 ? "sha1" : v.length === 64 ? "sha256" : null;
}

/**
 * Normalises one indicator, detecting its type when not given. Returns null
 * for anything that is not a well-formed indicator of that type — nothing is
 * resolved, fetched or looked up here.
 */
export function normalizeIndicator(value: string, type?: IndicatorType): Indicator | null {
  const v = value.trim();
  if (!v || v.length > 2_048 || /[\s\u0000-\u001f]/.test(v)) return null;
  const detect = (): IndicatorType | null => {
    if (net.isIP(v)) return "ip";
    if (/^https?:\/\//i.test(v)) return "url";
    if (CVE_RE.test(v.toUpperCase())) return "cve";
    if (hashKind(v)) return "hash";
    if (/^[^@\s]+@[^@\s]+$/.test(v)) return "email";
    if (/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$/.test(v)) return "domain";
    return null;
  };
  const t = type ?? detect();
  switch (t) {
    case "ip": return net.isIP(v) ? { type: "ip", value: v.toLowerCase() } : null;
    case "url": {
      try {
        const u = new URL(v);
        if (u.protocol !== "http:" && u.protocol !== "https:") return null;
        return { type: "url", value: u.toString() };
      } catch {
        return null;
      }
    }
    case "cve": return CVE_RE.test(v.toUpperCase()) ? { type: "cve", value: v.toUpperCase() } : null;
    case "hash": return hashKind(v) ? { type: "hash", value: v.toLowerCase() } : null;
    case "email": return /^[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$/.test(v) ? { type: "email", value: v.toLowerCase() } : null;
    case "domain": {
      const d = v.toLowerCase().replace(/\.$/, "");
      if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/.test(d) || d.length > 253) return null;
      return { type: "domain", value: d };
    }
    default: return null;
  }
}

/** Indicators mentioned in text (IPs, URLs, domains, hashes, CVEs, email addresses). */
export function extractIndicators(text: string, max = 100): Indicator[] {
  const out = new Map<string, Indicator>();
  const add = (i: Indicator | null) => {
    if (i && out.size < max) out.set(`${i.type}:${i.value}`, i);
  };
  const urls = text.match(URL_RE) ?? [];
  urls.forEach((u) => add(normalizeIndicator(u.replace(/[.,;:]+$/, ""), "url")));
  const withoutUrls = text.replace(URL_RE, " ");
  const emails = withoutUrls.match(EMAIL_RE) ?? [];
  emails.forEach((e) => add(normalizeIndicator(e, "email")));
  const rest = withoutUrls.replace(EMAIL_RE, " ");
  (rest.match(IPV4_RE) ?? []).forEach((ip) => add(normalizeIndicator(ip, "ip")));
  (rest.match(IPV6_RE) ?? []).filter((ip) => net.isIPv6(ip)).forEach((ip) => add(normalizeIndicator(ip, "ip")));
  (rest.match(CVE_TEXT_RE) ?? []).forEach((c) => add(normalizeIndicator(c, "cve")));
  (rest.match(HASH_RE) ?? []).forEach((h) => add(normalizeIndicator(h, "hash")));
  for (const d of rest.replace(IPV4_RE, " ").match(DOMAIN_RE) ?? []) {
    const tld = d.split(".").pop()!.toLowerCase();
    if (!NOT_A_TLD.has(tld)) add(normalizeIndicator(d, "domain"));
  }
  return [...out.values()];
}

/** Facts Legion can state about an IP without any lookup. */
export function localIpFacts(ip: string): string[] {
  const facts: string[] = [];
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) facts.push("private address (RFC 1918): not reachable from the internet");
    else if (a === 127) facts.push("loopback address");
    else if (a === 169 && b === 254) facts.push("link-local address");
    else if (a === 100 && b >= 64 && b <= 127) facts.push("carrier-grade NAT address (RFC 6598)");
    else if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0)) facts.push("reserved or documentation range");
  } else if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::1") facts.push("loopback address");
    else if (l.startsWith("fe80:")) facts.push("link-local address");
    else if (/^f[cd]/.test(l)) facts.push("unique local address: not reachable from the internet");
    else if (l.startsWith("2001:db8:")) facts.push("documentation range");
  }
  return facts;
}

/** Events that mention an indicator in their own fields or text. */
export function mentions(e: SecurityEvent, value: string): boolean {
  const v = value.toLowerCase();
  return [e.sourceIp, e.destinationIp, e.asset, e.user, e.title, e.summary, e.process, e.filePath]
    .some((f) => typeof f === "string" && f.toLowerCase().includes(v));
}
