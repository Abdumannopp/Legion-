import path from "node:path";
import type { FirewallPolicy } from "./policy.js";

/** Paths nobody's agent should read or write, whatever the roots say. */
export const SENSITIVE_PATH = /(^|\/)(\.env(\..*)?|\.ssh|\.gnupg|\.aws|\.kube|\.docker|id_rsa[^/]*|id_ed25519[^/]*|[^/]+\.(pem|key|p12|pfx|kdbx)|shadow|gshadow|sudoers|passwd|\.git-credentials|\.npmrc|\.pgpass)($|\/)|^\/(proc|sys|dev|boot|root)(\/|$)/i;

export interface PathVerdict {
  destination: string;
  problems: { id: string; reason: string }[];
}

/**
 * The one definition of which file paths an agent may touch. Used by the
 * firewall's file surface and by the tool gateway (files tool, shell
 * arguments, browser uploads), so the rules cannot drift apart.
 */
export function checkFilePath(policy: FirewallPolicy, p: string, mode: "read" | "write"): PathVerdict {
  if (p.includes("\0") || !path.isAbsolute(p)) {
    return {
      destination: `file:${p.replace(/\0/g, "\\0")}`,
      problems: [{ id: "file.bad_path", reason: "File paths must be absolute and contain no NUL bytes." }],
    };
  }
  const normalized = path.resolve(p);
  const problems: PathVerdict["problems"] = [];
  if (SENSITIVE_PATH.test(normalized)) problems.push({ id: "file.sensitive_path", reason: "Credentials, keys and system files are never accessible to agents." });
  const root = policy.files.roots.find((r) => {
    const rel = path.relative(path.resolve(r.path), normalized);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  });
  if (!root) problems.push({ id: "file.outside_roots", reason: "Path is outside every directory this organisation opened to agents." });
  else if (mode === "write" && root.access !== "readwrite") problems.push({ id: "file.read_only_root", reason: "This directory is read-only for agents." });
  return { destination: `file:${normalized}`, problems };
}
