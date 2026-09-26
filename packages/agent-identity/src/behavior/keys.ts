import path from "node:path";

/*
 * Destinations are compared at a useful granularity: a new host is new, a
 * new path on a known host is not; a new directory is new, a new file in a
 * known directory is not. Used by the profile, the assessment and the
 * firewall's novelty check, so all three agree.
 */
export function destinationKey(destination: string | null | undefined): string | null {
  if (!destination) return null;
  if (destination.startsWith("url:")) {
    try {
      return `url:${new URL(destination.slice(4)).host.toLowerCase()}`;
    } catch {
      return "url:(invalid)";
    }
  }
  if (destination.startsWith("file:")) return `file:${path.posix.dirname(destination.slice(5))}`;
  if (destination.startsWith("email:")) return `email:${destination.slice(6).split(",").sort().join(",")}`;
  return destination;
}

/** Destinations outside Legion: the web, mail, chat, code hosting, cloud, MCP servers. */
export function isExternal(key: string | null): boolean {
  return !!key && /^(?:url|email|slack|github|cloud|mcp):/.test(key) && key !== "email:mailbox";
}

export function isPeer(key: string | null): boolean {
  return !!key && key.startsWith("agent:");
}

/**
 * Rule hits that indicate intent rather than accident: an agent doing its
 * normal job does not try other tenants, internal addresses, interpreters
 * or permission laundering. They count even without a baseline.
 */
export const ATTACK_INDICATORS: ReadonlySet<string> = new Set([
  "tenant.mismatch", "sql.foreign_tenant", "db.tenant_filter", "sql.tenant_scope",
  "egress.internal_address", "egress.internal_name", "egress.resolved_internal", "egress.credentials_in_url",
  "http.host_override", "http.legion_secret", "egress.secret_in_payload",
  "shell.denied_command", "shell.dangerous_option", "shell.shell_syntax", "shell.path_escape",
  "db.protected_table", "sql.catalog_access", "sql.dangerous_function", "sql.multiple_statements", "sql.comments",
  "file.sensitive_path", "files.recursive_delete",
  "a2a.laundering", "a2a.injection_payload", "a2a.cycle", "a2a.message_invalid",
  "cloud.security_critical", "cloud.public_exposure", "cloud.public_principal",
  "mcp.definition_changed", "browser.credential_entry", "browser.script_execution",
  "github.pipeline_change", "github.force_push", "github.forbidden_operation",
  "email.sender_spoofing", "delegation.invalid", "sensitivity.restricted",
]);
