import type { Findings } from "./findings.js";

/*
 * Shell commands are the most dangerous tool an agent can have. Legion only
 * accepts them as a bare command name plus an argument list, executed without
 * a shell (execFile). On top of the tenant's allowlist, these commands are
 * refused outright — no policy can open them:
 */
export const DENIED_COMMANDS: ReadonlySet<string> = new Set([
  // interpreters and anything that runs another program
  "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox", "powershell", "pwsh", "cmd", "cmd.exe",
  "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua", "tclsh", "osascript",
  "java", "jshell", "irb", "eval", "exec", "env", "xargs", "nohup", "timeout", "nice", "ionice", "setsid", "stdbuf",
  "watch", "script", "expect", "find", "awk", "gawk", "mawk", "sed", "vim", "vi", "nano", "emacs", "less", "more", "man",
  "make", "tar", "zip", "unzip", "strace", "ltrace", "gdb", "lldb",
  // privilege
  "sudo", "su", "doas", "pkexec", "runuser", "chroot", "chmod", "chown", "chgrp", "chattr", "setfacl", "setcap",
  "passwd", "useradd", "userdel", "usermod", "groupadd", "visudo",
  // network: outbound calls go through the http tool, where destinations are checked
  "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "tftp", "openssl",
  "nslookup", "dig", "host", "ping",
  // destructive or system-wide
  "rm", "rmdir", "shred", "dd", "mkfs", "fdisk", "parted", "wipefs", "mount", "umount", "swapon", "swapoff",
  "kill", "killall", "pkill", "reboot", "shutdown", "halt", "poweroff", "init", "systemctl", "service", "launchctl",
  "crontab", "at", "batch", "iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "insmod", "rmmod", "modprobe",
  "docker", "podman", "kubectl", "helm", "terraform",
]);

/** Options that make otherwise harmless tools execute code or reconfigure themselves. */
const DANGEROUS_OPTION = /^(?:-c$|--exec(?:=|$)|--upload-pack|--receive-pack|--config(?:=|$)|--output(?:=|$)|-o$|--post-checkout|--to-command|--checkpoint-action|--use-compress-program|-e$|--eval|--import|--require|-r$|--init-file|--rcfile|--pager)/;
const CONFIG_KEYS = /\b(?:core\.(?:sshcommand|pager|editor|fsmonitor|hookspath|gitproxy)|alias\.|credential\.helper|protocol\.ext\.allow|filter\.[^=]*\.(?:clean|smudge)|diff\.[^=]*\.textconv|url\.[^=]*\.insteadof)/i;
/** Meaningless without a shell — present only when someone expects a shell to interpret them. */
const SHELL_SYNTAX = /\$\(|`|&&|\|\||(?:^|\s);\s*\S|\|\s*(?:sh|bash|zsh|python|perl|nc)\b|^\s*[<>]|>\s*\/|<\(|>\(/;

export function analyzeShell(
  call: { command: string; args: string[] },
  allow: Record<string, { subcommands?: string[]; maxArgs: number }>,
  f: Findings,
  checkPath: (arg: string) => void,
): void {
  const cmd = call.command.trim();
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(cmd)) {
    f.hard("shell.not_bare_command", "Commands must be a bare name from the allowlist — no paths, spaces or shell syntax.");
    return;
  }
  if (DENIED_COMMANDS.has(cmd.toLowerCase()) || /^(?:python|perl|ruby|php|node|mkfs)\d/.test(cmd.toLowerCase())) {
    f.hard("shell.denied_command", `${cmd} is never available to agents (interpreter, privilege, network or destructive).`);
    return;
  }
  const spec = allow[cmd];
  if (!spec) {
    f.hard("shell.not_allowlisted", `${cmd} is not on this organisation's shell allowlist.`);
    return;
  }
  if (call.args.length > spec.maxArgs) f.hard("shell.too_many_args", `At most ${spec.maxArgs} arguments.`);
  if (spec.subcommands && !spec.subcommands.includes(call.args[0] ?? "")) {
    f.hard("shell.subcommand", `${cmd} ${call.args[0] ?? "(none)"} is not allowed; allowed: ${spec.subcommands.join(", ")}.`);
  }
  for (const arg of call.args) {
    if (arg.includes("\0") || /[\r\n]/.test(arg)) f.hard("shell.control_chars", "Arguments cannot contain NUL or newlines.");
    if (DANGEROUS_OPTION.test(arg) || CONFIG_KEYS.test(arg)) f.hard("shell.dangerous_option", `Option ${arg.slice(0, 40)} can execute code or reconfigure the tool.`);
    if (SHELL_SYNTAX.test(arg)) f.hard("shell.shell_syntax", "Arguments contain shell syntax (substitution, chaining, redirection, pipes into interpreters).");
    // Anything that looks like a path must stay inside the file roots.
    if (arg.startsWith("/") || arg.startsWith("~") || arg.includes("../") || arg === "..") checkPath(arg);
  }
}
