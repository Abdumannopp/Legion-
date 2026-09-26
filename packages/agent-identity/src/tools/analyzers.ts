import path from "node:path";
import { PERMISSION_TIERS, type Permission } from "../permissions.js";
import { classifyUrl } from "../firewall/destinations.js";
import { checkFilePath } from "../firewall/paths.js";
import { PROTECTED_TABLES, type FirewallPolicy } from "../firewall/policy.js";
import { byteSize, findSecrets, findUrls, hashToolDefinition } from "../firewall/scan.js";
import type { Sensitivity } from "../firewall/types.js";
import type { MachinePrincipal } from "../types.js";
import { Findings } from "./findings.js";
import { analyzeShell } from "./shell.js";
import { analyzeSql } from "./sql.js";
import type { ToolAnalysis, ToolCall } from "./types.js";

/*
 * One deterministic analyser per tool family. Each answers: what is the
 * target, where does the effect land, which permission does it need, how
 * sensitive is it, does it change state or act outside Legion, and which
 * dangerous patterns does it contain. Nothing here does I/O.
 */

const EXECUTABLE = /\.(?:exe|msi|bat|cmd|com|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|scr|pif|cpl|dll|sys|jar|apk|app|dmg|pkg|deb|rpm|sh|bash|run|bin|iso|img|lnk|reg|msix|appx)$/i;
const CREDENTIAL_FIELD = /pass(?:word|wd|phrase)?|pwd|secret|token|otp|2fa|mfa|totp|pin\b|cvv|cvc|card.?num|credit.?card|iban|ssn|social.?security|api.?key|private.?key/i;
const MASS_MENTION = /<!(?:channel|here|everyone)>|@(?:channel|here|everyone)\b/i;

interface Ctx {
  principal: MachinePrincipal;
  policy: FirewallPolicy;
}

type Base = Omit<ToolAnalysis, "hits" | "factors" | "highRisk">;

function secrets(value: unknown, f: Findings, id: string, what: string): void {
  const found = findSecrets(value);
  if (found.length) f.hard(id, `${what} contains credentials (${found.join(", ")}).`);
}

function url(u: string, policy: FirewallPolicy, f: Findings): string {
  const v = classifyUrl(u, policy.egress.allowedHosts, policy.egress.allowedPorts);
  if (!v.ok) (v.hard ? f.hard.bind(f) : f.soft.bind(f))(v.rule, v.reason);
  return v.normalized ? `url:${v.normalized}` : "url:(invalid)";
}

function filePath(p: string, mode: "read" | "write", policy: FirewallPolicy, f: Findings): string {
  const v = checkFilePath(policy, p, mode);
  for (const pr of v.problems) f.hard(pr.id, pr.reason);
  return v.destination;
}

function analyzeBrowser(c: Extract<ToolCall, { kind: "browser" }>, { policy }: Ctx, f: Findings): Base {
  const destination = url(c.url, policy, f);
  const write = !["navigate", "read_page", "screenshot"].includes(c.operation);
  switch (c.operation) {
    case "execute_script":
      f.hard("browser.script_execution", "Running arbitrary script in a page is never allowed.");
      break;
    case "fill_form":
    case "submit_form": {
      const fields = c.fields ?? {};
      const cred = Object.keys(fields).find((k) => CREDENTIAL_FIELD.test(k));
      if (cred) f.hard("browser.credential_entry", `Agents do not type credentials or payment data into pages (field "${cred.slice(0, 40)}").`);
      secrets(fields, f, "browser.secret_in_form", "The form");
      f.add("submits data to a site", 5);
      break;
    }
    case "download":
      if (!policy.toolSecurity.browser.allowDownloads) f.soft("browser.downloads_disabled", "Downloads are disabled for agents.");
      if (EXECUTABLE.test(c.filename ?? c.url.split(/[?#]/)[0]!)) f.hard("browser.executable_download", "Executable or installer downloads are never allowed.");
      break;
    case "upload":
      if (!c.uploadPath) f.hard("browser.upload_without_file", "An upload must name the file.");
      else filePath(c.uploadPath, "read", policy, f);
      f.add("sends a file to a site", 10);
      break;
  }
  return {
    toolKind: "browser", operation: c.operation, target: c.url.slice(0, 500), destination,
    permission: write ? "tool.browser:write" : "tool.browser:read", sensitivity: "internal",
    changesState: write, externalEffect: true,
  };
}

function analyzeHttp(c: Extract<ToolCall, { kind: "http" }>, { policy }: Ctx, f: Findings): Base {
  const method = c.method.toUpperCase();
  if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(method)) f.hard("egress.method", `HTTP method ${c.method} is not allowed.`);
  const destination = url(c.url, policy, f);
  const headers = Object.fromEntries(Object.entries(c.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
  if (headers.host || headers["x-forwarded-host"] || headers["x-original-url"] || headers["x-rewrite-url"]) {
    f.hard("http.host_override", "Overriding the Host or routing headers is not allowed.");
  }
  // Credentials the agent needs for the destination's API may travel in the
  // auth headers (the destination is allowlisted); anywhere else they are
  // exfiltration. Legion's own secrets never leave.
  const legion = findSecrets({ headers, body: c.body, url: c.url }).filter((s) => s.startsWith("legion_"));
  if (legion.length) f.hard("http.legion_secret", "Legion credentials must never be sent to another service.");
  const { authorization, "x-api-key": apiKey, ...otherHeaders } = headers;
  if (findSecrets(authorization ?? "").length || findSecrets(apiKey ?? "").length) f.add("sends an API credential", 5);
  secrets({ otherHeaders, body: c.body, url: c.url }, f, "egress.secret_in_payload", "The request");
  const write = !["GET", "HEAD"].includes(method);
  return {
    toolKind: "http", operation: `${method.toLowerCase()}`, target: c.url.slice(0, 500), destination,
    permission: write ? "tool.http:write" : "tool.http:read", sensitivity: "confidential",
    changesState: write, externalEffect: true,
  };
}

function analyzeDatabase(c: Extract<ToolCall, { kind: "database" }>, { principal, policy }: Ctx, f: Findings): Base {
  const r = analyzeSql(c.sql, c.params, {
    tenantId: principal.tenantId,
    maxRows: policy.database.maxRows,
    tables: policy.database.tables,
    protectedTables: PROTECTED_TABLES,
  }, f);
  if (r.verb === "delete") f.add("deletes rows", 10);
  const write = r.verb !== "select";
  return {
    toolKind: "database", operation: r.verb ?? "unknown", target: r.tables.join(",") || "(none)",
    destination: `db:${r.tables.join(",") || "(none)"}`,
    permission: write ? "tool.database:write" : "tool.database:read", sensitivity: "internal",
    changesState: write, externalEffect: false,
  };
}

function analyzeFiles(c: Extract<ToolCall, { kind: "files" }>, { policy }: Ctx, f: Findings): Base {
  const write = ["write", "delete", "move"].includes(c.operation);
  const destination = filePath(c.path, write ? "write" : "read", policy, f);
  if (c.operation === "move") {
    if (!c.destinationPath) f.hard("files.move_without_destination", "A move must name its destination.");
    else filePath(c.destinationPath, "write", policy, f);
  }
  if (c.operation === "delete") {
    f.add("deletes a file", 10);
    if (c.recursive) f.hard("files.recursive_delete", "Recursive deletion is never available to agents.");
  }
  if (c.operation === "write" && c.content !== undefined) {
    if (findSecrets(c.content).length) f.warn("files.secret_written", "Credentials are being written to a file.");
    if (EXECUTABLE.test(c.path)) f.hard("files.executable_write", "Agents cannot write executables or scripts.");
  }
  return {
    toolKind: "files", operation: c.operation, target: path.resolve(c.path.replace(/\0/g, "")), destination,
    permission: write ? "tool.files:write" : "tool.files:read", sensitivity: "internal",
    changesState: write, externalEffect: false,
  };
}

function analyzeShellCall(c: Extract<ToolCall, { kind: "shell" }>, { policy }: Ctx, f: Findings): Base {
  analyzeShell(c, policy.toolSecurity.shell.commands, f, (arg) => {
    if (arg.startsWith("~") || !path.isAbsolute(arg)) {
      f.hard("shell.path_escape", `Argument ${arg.slice(0, 60)} leaves the working directory.`);
    } else filePath(arg, "write", policy, f);
  });
  if (c.cwd) filePath(c.cwd, "write", policy, f);
  else if (!policy.files.roots.some((r) => r.access === "readwrite")) f.hard("shell.no_workdir", "Shell commands need a read-write file root to run in.");
  secrets(c.args, f, "shell.secret_in_args", "The command line");
  return {
    toolKind: "shell", operation: "execute", target: [c.command, ...c.args].join(" ").slice(0, 500),
    destination: `shell:${c.command}`, permission: "tool.shell:execute", sensitivity: "confidential",
    changesState: true, externalEffect: false,
  };
}

function domainOf(address: string): string | null {
  const m = /^[^@\s<>"]+@([a-z0-9.-]+\.[a-z]{2,})$/i.exec(address.trim());
  return m ? m[1]!.toLowerCase() : null;
}

function analyzeEmail(c: Extract<ToolCall, { kind: "email" }>, { policy }: Ctx, f: Findings): Base {
  const cfg = policy.toolSecurity.email;
  const sending = ["send", "reply", "forward"].includes(c.operation);
  const recipients = [...c.to, ...c.cc, ...c.bcc];
  const domains = [...new Set(recipients.map((r) => domainOf(r) ?? "(invalid)"))];
  if (sending) {
    if (!recipients.length) f.hard("email.no_recipients", "A message needs recipients.");
    if (recipients.some((r) => !domainOf(r))) f.hard("email.invalid_address", "Recipient addresses must be plain name@domain.");
    const outside = domains.filter((d) => !cfg.allowedRecipientDomains.some((a) => d === a || d.endsWith(`.${a}`)));
    if (outside.length) f.hard("email.recipient_not_allowed", `Recipients outside this organisation's allowed domains: ${outside.join(", ")}.`);
    if (recipients.length > cfg.maxRecipients) f.hard("email.bulk_send", `${recipients.length} recipients exceeds ${cfg.maxRecipients}.`);
    if (c.bcc.length) f.warn("email.bcc", "Blind copies hide recipients from the people who read the message.");
    if (c.from && !cfg.allowedSenders.includes(c.from.toLowerCase())) f.hard("email.sender_spoofing", "Agents cannot choose an arbitrary sender address.");
    if (c.attachments.length) {
      if (!cfg.allowAttachments) f.soft("email.attachments_disabled", "Attachments are disabled for agents.");
      if (c.attachments.some((a) => EXECUTABLE.test(a.filename))) f.hard("email.executable_attachment", "Executable attachments are never allowed.");
    }
    secrets({ subject: c.subject, body: c.body, attachments: c.attachments.map((a) => a.filename) }, f, "email.secret_in_message", "The message");
    if (c.operation === "forward") f.add("forwards existing mail", 10);
  }
  if (c.operation === "delete" && c.messageIds.length > 50) f.hard("email.bulk_delete", "Agents cannot delete more than 50 messages at once.");
  const write = sending || c.operation === "delete" || c.operation === "move";
  return {
    toolKind: "email", operation: c.operation,
    target: sending ? recipients.join(",").slice(0, 500) : (c.messageIds.join(",") || c.query || "(mailbox)").slice(0, 500),
    destination: sending ? `email:${domains.join(",")}` : "email:mailbox",
    permission: write ? "tool.email:write" : "tool.email:read", sensitivity: "confidential",
    changesState: write, externalEffect: sending,
  };
}

const GITHUB_READ = new Set(["read_repo", "read_file", "list_issues", "read_issue", "read_pr", "search_code"]);
/** Never by an agent: merging, deleting, access, secrets, CI and release supply chain. */
const GITHUB_FORBIDDEN = new Set([
  "merge_pr", "delete_branch", "delete_repo", "change_visibility", "update_settings", "add_collaborator", "remove_collaborator",
  "create_deploy_key", "manage_secrets", "manage_webhooks", "update_branch_protection", "create_release", "workflow_dispatch",
]);
const PROTECTED_BRANCH = /^(?:main|master|trunk|develop|production|prod|release|stable|gh-pages)(?:[/-].*)?$|^(?:release|hotfix|prod)\//i;

function analyzeGithub(c: Extract<ToolCall, { kind: "github" }>, { policy }: Ctx, f: Findings): Base {
  const access = policy.toolSecurity.github.repos[c.repo];
  const write = !GITHUB_READ.has(c.operation);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(c.repo)) f.hard("github.bad_repo", "Repositories are named owner/repo.");
  else if (!access) f.hard("github.repo_not_allowed", `${c.repo} is not opened to agents.`);
  else if (write && access !== "write") f.hard("github.read_only", `${c.repo} is read-only for agents.`);
  if (GITHUB_FORBIDDEN.has(c.operation)) f.hard("github.forbidden_operation", `${c.operation} is never done by an agent — it needs a person.`);
  if (["push_commit", "create_branch"].includes(c.operation)) {
    if (!c.branch) f.hard("github.no_branch", "Pushes must name a branch.");
    else if (PROTECTED_BRANCH.test(c.branch)) f.hard("github.protected_branch", `Agents cannot push to ${c.branch}; open a pull request from a feature branch.`);
    if (c.force) f.hard("github.force_push", "Force-pushing rewrites history and is never allowed.");
  }
  const touched = c.files.map((x) => x.path);
  if (touched.some((p) => /^\.github\/|(^|\/)(?:CODEOWNERS|\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines\.yml|\.circleci\/)/.test(p))) {
    f.hard("github.pipeline_change", "Changing CI/CD, workflow or ownership files is a supply-chain risk and needs a person.");
  }
  if (touched.some((p) => /(^|\/)(?:package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|poetry\.lock|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|Gemfile(?:\.lock)?|pom\.xml|build\.gradle)$/.test(p))) {
    f.warn("github.dependency_change", "Dependency manifests are changed.");
  }
  secrets({ files: c.files, title: c.title, body: c.body }, f, "github.secret_in_content", "The content");
  return {
    toolKind: "github", operation: c.operation, target: `${c.repo}${c.branch ? `@${c.branch}` : ""}`.slice(0, 500),
    destination: `github:${c.repo}`, permission: write ? "tool.github:write" : "tool.github:read", sensitivity: "internal",
    changesState: write, externalEffect: write,
  };
}

function analyzeSlack(c: Extract<ToolCall, { kind: "slack" }>, { policy }: Ctx, f: Findings): Base {
  const cfg = policy.toolSecurity.slack;
  const write = c.operation !== "read_channel";
  if (["invite_user", "create_channel", "archive_channel", "set_topic"].includes(c.operation)) {
    f.hard("slack.forbidden_operation", `${c.operation} changes the workspace and needs a person.`);
  }
  if (c.operation === "dm_user") {
    if (!cfg.allowDirectMessages) f.soft("slack.direct_messages_disabled", "Direct messages from agents are disabled.");
  } else {
    const access = cfg.channels[c.channel];
    if (!access) f.hard("slack.channel_not_allowed", `Channel ${c.channel.slice(0, 30)} is not opened to agents.`);
    else if (write && access !== "write") f.hard("slack.read_only", `Channel ${c.channel} is read-only for agents.`);
  }
  if (c.text && MASS_MENTION.test(c.text) && !cfg.allowMassMentions) f.soft("slack.mass_mention", "@channel / @here / @everyone from an agent is disabled.");
  if (c.operation === "upload_file") {
    if (!cfg.allowUploads) f.soft("slack.uploads_disabled", "File uploads by agents are disabled.");
    if (c.filename && EXECUTABLE.test(c.filename)) f.hard("slack.executable_upload", "Executable uploads are never allowed.");
  }
  secrets({ text: c.text, filename: c.filename }, f, "slack.secret_in_message", "The message");
  for (const u of findUrls(c.text ?? "")) {
    if (/^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(u)) f.warn("slack.raw_ip_link", "The message links to a raw IP address.");
  }
  return {
    toolKind: "slack", operation: c.operation, target: c.operation === "dm_user" ? `user:${c.userId ?? "?"}` : c.channel,
    destination: `slack:${c.operation === "dm_user" ? `dm:${c.userId ?? "?"}` : c.channel}`,
    permission: write ? "tool.slack:write" : "tool.slack:read", sensitivity: "internal",
    changesState: write, externalEffect: write,
  };
}

function analyzeMcp(c: Extract<ToolCall, { kind: "mcp" }>, { principal, policy }: Ctx, f: Findings): Base {
  const server = policy.mcp.servers[c.server];
  const spec = server?.tools[c.definition.name];
  if (!server) f.hard("mcp.unknown_server", `MCP server ${c.server} is not approved.`);
  else if (!spec) f.hard("mcp.unknown_tool", `MCP tool ${c.definition.name} is not approved on ${c.server}.`);
  else if (spec.sha256 !== hashToolDefinition(c.definition)) {
    f.hard("mcp.definition_changed", "The tool's advertised definition no longer matches the approved one (possible tool poisoning). Review and re-approve it.");
  }
  if (spec) {
    if (spec.permission && !principal.permissions.includes(spec.permission)) f.hard("mcp.permission_not_granted", `This MCP tool needs ${spec.permission}.`);
    if (spec.allowedArgs) {
      const extra = Object.keys(c.args).filter((k) => !spec.allowedArgs!.includes(k));
      if (extra.length) f.hard("mcp.unexpected_args", `Arguments not declared for this tool: ${extra.join(", ")}`);
    }
    if (byteSize(c.args) > spec.maxArgBytes) f.hard("mcp.args_too_large", `Arguments exceed ${spec.maxArgBytes} bytes.`);
    if (spec.sideEffects === "external") for (const u of findUrls(c.args)) url(u, policy, f);
  }
  secrets(c.args, f, "mcp.secret_in_args", "The arguments");
  const write = !spec || spec.sideEffects !== "none";
  return {
    toolKind: "mcp", operation: "call_tool", target: `${c.server}/${c.definition.name}`, destination: `mcp:${c.server}/${c.definition.name}`,
    permission: write ? "tool.mcp:write" : "tool.mcp:read", sensitivity: (spec?.sensitivity ?? "internal") as Sensitivity,
    changesState: write, externalEffect: spec?.sideEffects === "external",
  };
}

/** Provider actions that change identity, audit or exposure: never by an agent, whatever the policy. */
const CLOUD_CRITICAL: RegExp[] = [
  /^iam:/i, /^sts:assumerole/i, /^organizations:/i, /^sso:/i, /^identitystore:/i,
  /^kms:(?:disable|schedulekeydeletion|putkeypolicy|creategrant|revoke|decrypt)/i,
  /^cloudtrail:(?:stoplogging|deletetrail|updatetrail|puteventselectors)/i,
  /^(?:guardduty|securityhub|macie2?|inspector2?|detective):(?:delete|disable|update|stop)/i,
  /^config:(?:stop|delete)/i, /^logs:(?:delete|putretentionpolicy)/i,
  /^s3:(?:putbucketpolicy|putbucketacl|putobjectacl|deletebucketpolicy|putpublicaccessblock|deletepublicaccessblock|putbucketpublicaccessblock)/i,
  /^secretsmanager:(?:getsecretvalue|putsecretvalue|deletesecret)/i, /^ssm:(?:sendcommand|startsession|getparameters?$)/i,
  /^lambda:(?:addpermission|updatefunctioncode|createfunction)/i, /^ec2:(?:modifyinstanceattribute|createkeypair|importkeypair)/i,
  /\.setiampolicy$/i, /^iam\./i, /^resourcemanager\./i, /^logging\.(?:sinks|buckets)\.(?:delete|update)/i,
  /^secretmanager\.versions\.access/i, /^cloudkms\./i, /^compute\.instances\.setmetadata/i,
  /^microsoft\.authorization\//i, /^microsoft\.keyvault\/vaults\/(?:secrets|keys)\//i, /^microsoft\.insights\/diagnosticsettings\/delete/i,
  /^microsoft\.security\//i,
];
const CLOUD_READ = /(?::|\.|\/)(?:get|list|describe|head|lookup|search|read|view|batchget|scan|query)[a-z]*$/i;
const CLOUD_DESTRUCTIVE = /(?::|\.|\/)(?:delete|terminate|destroy|remove|purge|detach|deregister|disable|drop|release|cancel|stop)[a-z]*$/i;

function analyzeCloud(c: Extract<ToolCall, { kind: "cloud" }>, { policy }: Ctx, f: Findings): Base {
  const cfg = policy.toolSecurity.cloud;
  const acct = cfg.accounts.find((a) => a.provider === c.provider && a.account === c.account);
  const read = CLOUD_READ.test(c.action);
  const destructive = !read && CLOUD_DESTRUCTIVE.test(c.action);
  if (!acct) f.hard("cloud.account_not_allowed", `${c.provider} account ${c.account} is not opened to agents.`);
  else {
    if (acct.regions.length && (!c.region || !acct.regions.includes(c.region))) f.hard("cloud.region_not_allowed", `Region ${c.region ?? "(none)"} is not allowed for this account.`);
    if (!read && acct.access !== "write") f.hard("cloud.read_only", "This account is read-only for agents.");
  }
  if (CLOUD_CRITICAL.some((re) => re.test(c.action))) {
    f.hard("cloud.security_critical", `${c.action} changes identity, secrets, logging or exposure and is never done by an agent.`);
  }
  if (destructive) {
    if (!cfg.allowDestructive) f.hard("cloud.destructive", `${c.action} deletes or stops resources; destructive actions are disabled for agents.`);
    else f.add("destructive cloud action", 5);
  }
  const p = JSON.stringify(c.params);
  if (/(?:"|\b)(?:0\.0\.0\.0\/0|::\/0)(?:"|\b)/.test(p)) f.hard("cloud.public_exposure", "Opening a resource to the whole internet (0.0.0.0/0, ::/0) is never allowed.");
  if (/"principal"\s*:\s*(?:"\*"|\{\s*"aws"\s*:\s*"\*"\s*\})|allusers|allauthenticatedusers/i.test(p)) f.hard("cloud.public_principal", "Granting access to everyone is never allowed.");
  secrets(c.params, f, "cloud.secret_in_params", "The parameters");
  return {
    toolKind: "cloud", operation: c.action, target: (c.resource ?? c.action).slice(0, 500),
    destination: `cloud:${c.provider}:${c.account}:${c.region ?? "global"}`,
    permission: read ? "tool.cloud:read" : "tool.cloud:write", sensitivity: "internal",
    changesState: !read, externalEffect: !read,
  };
}

export function analyzeToolCall(call: ToolCall, ctx: Ctx): ToolAnalysis {
  const f = new Findings();
  let base: Base;
  switch (call.kind) {
    case "browser": base = analyzeBrowser(call, ctx, f); break;
    case "http": base = analyzeHttp(call, ctx, f); break;
    case "database": base = analyzeDatabase(call, ctx, f); break;
    case "files": base = analyzeFiles(call, ctx, f); break;
    case "shell": base = analyzeShellCall(call, ctx, f); break;
    case "email": base = analyzeEmail(call, ctx, f); break;
    case "github": base = analyzeGithub(call, ctx, f); break;
    case "slack": base = analyzeSlack(call, ctx, f); break;
    case "mcp": base = analyzeMcp(call, ctx, f); break;
    case "cloud": base = analyzeCloud(call, ctx, f); break;
  }
  const tier = base.permission ? PERMISSION_TIERS[base.permission as Permission] : 0;
  return {
    ...base,
    highRisk: tier >= 2 || f.hits.length > 0,
    hits: f.hits,
    factors: f.factors,
  };
}

/** A call that did not match any known shape: still a decision, still audited. */
export function invalidCallAnalysis(raw: unknown, reason: string): ToolAnalysis {
  const kind = raw && typeof raw === "object" && typeof (raw as { kind?: unknown }).kind === "string" ? String((raw as { kind: string }).kind).slice(0, 40) : "unknown";
  const operation = raw && typeof raw === "object" && typeof (raw as { operation?: unknown }).operation === "string" ? String((raw as { operation: string }).operation).slice(0, 60) : "unknown";
  const f = new Findings();
  f.hard("tool.invalid_call", `Not a valid tool call: ${reason}`);
  return {
    toolKind: "unknown", operation: `${kind}.${operation}`, target: "(invalid)", destination: `tool:${kind}`,
    permission: null, sensitivity: "internal", changesState: false, externalEffect: false, highRisk: true,
    hits: f.hits, factors: f.factors,
  };
}
