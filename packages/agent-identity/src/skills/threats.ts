/*
 * The seven attack types Legion watches for, and what each one looks like in
 * the logs a sensor sends. Shared by the server (real-time campaign
 * detection) and by the skills (coverage and analysis), so both read the
 * same evidence the same way.
 *
 * Everything here is a pattern over event text. Event text can be written by
 * an attacker; a match is a lead to check, never an instruction.
 */

export const THREATS = ["ransomware", "bec", "phishing", "ddos", "ai_deception", "espionage", "supply_chain"] as const;
export type Threat = (typeof THREATS)[number];

export interface ThreatSign {
  id: string;
  threat: Threat;
  label: string;
  /** Strong: on its own it is worth an alert. Weak: only in combination. */
  strong: boolean;
  re: RegExp;
  /**
   * The MITRE ATT&CK technique (parent id) the matched text itself shows. Only where the sign is
   * evidence of that exact behaviour; absent when the sign is too generic to name one.
   */
  technique?: string;
}

export const THREAT_SIGNS: readonly ThreatSign[] = [
  // ---- Ransomware: encrypt files, delete the way back, demand payment ----------------
  { id: "ransom_note", technique: "T1486", threat: "ransomware", label: "Ransom note", strong: true,
    re: /\b(?:ransom (?:note|demand|message)|your (?:files|data) (?:have been|are|were) encrypted|how[_ -]to[_ -](?:decrypt|restore)[_ -](?:your[_ -])?files|readme[_ -](?:for|to)[_ -]decrypt|decrypt(?:ion)? instructions)\b/i },
  { id: "shadow_copy_delete", technique: "T1490", threat: "ransomware", label: "Shadow copies deleted", strong: true,
    re: /\b(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|shadow ?cop(?:y|ies) (?:were |was )?(?:deleted|removed))\b/i },
  { id: "recovery_disabled", technique: "T1490", threat: "ransomware", label: "System recovery disabled", strong: true,
    re: /\b(?:bcdedit(?:\.exe)?[^\n]{0,60}recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup))\b/i },
  { id: "files_encrypted", technique: "T1486", threat: "ransomware", label: "Files encrypted or mass-renamed", strong: true,
    re: /\b(?:files? (?:were |was |being )?encrypted|mass (?:file )?(?:encryption|rename|renaming)|encrypted (?:file )?extension)\b/i },
  { id: "file_change", threat: "ransomware", label: "File changed, added or deleted", strong: false,
    re: /\b(?:integrity checksum changed|file (?:was )?(?:modified|deleted|added|created|renamed)|syscheck)\b/i },

  // ---- Business Email Compromise: take over a mailbox, redirect the money --------------
  { id: "mail_forwarding", technique: "T1114", threat: "bec", label: "Mail forwarded or redirected outside", strong: true,
    re: /\b(?:(?:new|set)-(?:inboxrule|mailbox)\b[^\n]{0,600}\b(?:forward\w*|redirect\w*)|inbox ?rule[^\n]{0,120}\b(?:forward\w*|redirect\w*)|forwardingsmtpaddress|forwarding ?address (?:set|added|changed)|mail(?:box)? forwarding (?:enabled|set|added)|auto-?forward\w*[^\n]{0,30}external)\b/i },
  { id: "mail_hiding_rule", technique: "T1564", threat: "bec", label: "Inbox rule hiding messages", strong: true,
    re: /\binbox ?rule[^\n]{0,120}\b(?:delete\w*|mark(?:ed)? as read|move\w* to (?:rss|archive|conversation history|deleted items))\b/i },
  { id: "oauth_consent", technique: "T1528", threat: "bec", label: "Application given access to the mailbox", strong: true,
    re: /\b(?:consent to application|oauth (?:app(?:lication)?|token) (?:consent|granted|authori[sz]ed)|add (?:delegated )?(?:permission|oauth2permission) grant|illicit consent)\b/i },
  { id: "mfa_removed", technique: "T1556", threat: "bec", label: "Second factor removed or reset", strong: true,
    re: /\b(?:(?:mfa|multi-?factor|two-?factor|2fa|authenticator)[^\n]{0,40}\b(?:disabled|removed|deleted|turned off|reset)|(?:disabled|removed|deleted|reset)\b[^\n]{0,20}\b(?:mfa|multi-?factor|2fa))\b/i },
  { id: "payment_change", technique: "T1657", threat: "bec", label: "Payment details changed", strong: true,
    re: /\b(?:(?:bank|payment) (?:account|details|information) (?:changed|updated|modified)|(?:vendor|supplier|beneficiary|payee) (?:bank )?(?:details|account) (?:changed|updated|added)|iban (?:changed|updated))\b/i },

  // ---- Phishing: a lure, a click, a document that runs code -----------------------------
  { id: "office_spawned_script", technique: "T1204", threat: "phishing", label: "Office document started a script", strong: true,
    // Either order: Sysmon JSON names the child ("image") before the parent ("parentImage").
    re: /\b(?:winword|excel|powerpnt|outlook|onenote)(?:\.exe)?\b[^\n]{0,120}\b(?:powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)\b|\b(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe\b[^\n]{0,600}\bparent ?image"?\s*[:=]\s*"?[^"\n]{0,200}\b(?:winword|excel|powerpnt|outlook|onenote)\.exe/i },
  { id: "malicious_link_click", technique: "T1204", threat: "phishing", label: "Malicious link clicked", strong: true,
    re: /\b(?:clicked (?:on )?(?:a |an )?(?:malicious|suspicious|phishing) (?:link|url)|(?:malicious|phishing) (?:url|link|site) (?:was )?(?:visited|clicked|opened|accessed))\b/i },
  { id: "macro_executed", technique: "T1204", threat: "phishing", label: "Macro executed", strong: true,
    re: /\b(?:malicious macro|macro (?:was )?(?:executed|enabled|ran)|vba macro (?:executed|detected))\b/i },
  { id: "phishing_message", technique: "T1566", threat: "phishing", label: "Phishing message", strong: false,
    re: /\b(?:phish\w*|credential harvest\w*|lookalike domain|spoofed sender|sender spoof\w*)\b/i },

  // ---- DDoS: overwhelm the service --------------------------------------------------------
  { id: "flood", technique: "T1498", threat: "ddos", label: "Flood or denial of service", strong: true,
    re: /\b(?:ddos|denial[- ]of[- ]service|syn flood|udp flood|http flood|request flood|amplification attack)\b/i },
  { id: "overload", threat: "ddos", label: "Rate limit or connection limit hit", strong: false,
    re: /\b(?:rate limit (?:exceeded|reached)|too many (?:requests|connections)|connection limit (?:exceeded|reached))\b/i },

  // ---- AI deception: impersonation with synthetic voice, video or text -------------------
  { id: "impersonation", technique: "T1656", threat: "ai_deception", label: "Impersonation or synthetic media", strong: true,
    re: /\b(?:deep ?fake|voice clon\w*|cloned voice|synthetic (?:voice|video|media)|ceo fraud|executive impersonation|impersonat\w+ (?:the |a |an )?(?:ceo|cfo|executive|director|manager))\b/i },

  // ---- Cyber espionage: get in quietly, stay, take data over time -----------------------
  { id: "credential_dumping", technique: "T1003", threat: "espionage", label: "Credential dumping", strong: true,
    re: /\b(?:mimikatz|sekurlsa|lsass(?:\.exe)? (?:memory )?(?:dump|access)|ntds\.dit|dcsync)\b/i },
  { id: "c2_beacon", technique: "T1071", threat: "espionage", label: "Command-and-control or beaconing", strong: true,
    re: /\b(?:beacon\w*|command[- ]and[- ]control|\bc2\b|dns tunnel\w*|cobalt ?strike)\b/i },
  { id: "persistence", threat: "espionage", label: "Persistence set up", strong: false,
    re: /\b(?:scheduled task (?:created|registered)|new (?:service|run key|startup item) (?:installed|created|added)|crontab (?:modified|changed)|registry run key)\b/i },

  // ---- Supply chain: trusted software or a vendor brings the attacker in ---------------
  { id: "integrity_failure", threat: "supply_chain", label: "Signature or checksum failed", strong: true,
    re: /\b(?:signature (?:verification )?(?:failed|invalid|mismatch)|(?:checksum|hash) mismatch|untrusted (?:publisher|signature|certificate)|unsigned (?:binary|driver|package|update))\b/i },
  { id: "malicious_package", technique: "T1195", threat: "supply_chain", label: "Malicious or compromised package", strong: true,
    re: /\b(?:malicious (?:package|dependency|library|npm package|pypi package)|typosquat\w*|dependency confusion|compromised (?:update|package|dependency|library|vendor))\b/i },
  { id: "software_install", threat: "supply_chain", label: "Software installed or updated", strong: false,
    re: /\b(?:new (?:dpkg|rpm)?\s?\(?(?:debian )?package\)? installed|package (?:installed|updated|upgraded)|(?:npm|pip|gem) install|software (?:installed|updated)|msiexec)\b/i },
];

/** Every sign the text shows. */
export function threatSigns(text: string): ThreatSign[] {
  const t = String(text ?? "").slice(0, 20_000);
  return THREAT_SIGNS.filter((s) => s.re.test(t));
}

/** The threats a text points at, strong signs only. */
export function strongThreats(text: string): Threat[] {
  return [...new Set(threatSigns(text).filter((s) => s.strong).map((s) => s.threat))];
}

/** Signs that a later event shows the attacker active on the host (for supply chain: what came after an install). */
export const ACTIVITY_AFTER_INSTALL = /\b(?:reverse shell|bash -i|powershell(?:\.exe)? -enc|outbound connection|command[- ]and[- ]control|\bc2\b|beacon\w*|new (?:service|scheduled task)|suspicious process)\b/i;

/**
 * What data a sensor must send for Legion to see each threat. Legion can only
 * detect what reaches it; this says what to look for in the events to know a
 * source is connected.
 */
export const THREAT_SOURCES: Record<Threat, { re: RegExp; connect: string }> = {
  ransomware: { re: /\b(?:integrity checksum|syscheck|file (?:added|deleted|modified)|process (?:created|started)|sysmon|windows defender|edr)\b/i,
    connect: "File integrity monitoring (Wazuh syscheck) and process events from servers and workstations." },
  bec: { re: /\b(?:office ?365|microsoft 365|exchange|mailbox|azure ad|entra|google workspace|gmail|inbox ?rule)\b/i,
    connect: "Microsoft 365 or Google Workspace audit logs (Wazuh office365 / gcp-pubsub module)." },
  phishing: { re: /\b(?:email|e-mail|mail gateway|safe ?links|attachment|winword|outlook|proxy|url filter)\b/i,
    connect: "Email security gateway or Microsoft Defender for Office logs, plus process events from workstations." },
  ddos: { re: /\b(?:web server|nginx|apache|iis|http|firewall|waf|cloudflare|load balancer)\b/i,
    connect: "Web server, firewall or WAF logs; for protection, an edge service such as Cloudflare in front of the site." },
  ai_deception: { re: /\b(?:office ?365|exchange|mailbox|teams|zoom|call|voice)\b/i,
    connect: "Mailbox audit logs catch what follows a deepfake (payment change, forwarding). The call or video itself never reaches Legion." },
  espionage: { re: /\b(?:process (?:created|started)|sysmon|auditd|powershell|outbound connection|dns)\b/i,
    connect: "Process, PowerShell and outbound-connection (DNS/firewall) events from servers and workstations." },
  supply_chain: { re: /\b(?:dpkg|rpm|yum|apt(?:-get)?|msiexec|npm|pip|package (?:installed|updated|upgraded|removed)|software (?:installed|updated)|code[- ]signing|signature verification)\b/i,
    connect: "Package-install and software-update events (Wazuh logs dpkg/rpm installs) and code-signing failures." },
};
