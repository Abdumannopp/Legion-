"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  BrainCircuit, CheckCircle2, ChevronDown, ChevronRight, KeyRound, Loader2, Plug, Send, ShieldAlert, Trash2,
} from "lucide-react";
import Sidebar from "@/components/Sidebar";
import ErrorNotice from "@/components/ErrorNotice";
import CopyButton from "@/components/CopyButton";
import {
  ApiError, createSensorKey, getIntegrationCatalogue, getMe, getSensorKeys, isLoggedIn, revokeSensorKey, sendTestAlert,
  webhookUrl, type CurrentUser, type IntegrationInfo, type IssuedSensorKey, type SensorKey,
} from "@/lib/api";
import { timeAgo } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const POLL_MS = 5000;

/** The ossec.conf block for this workspace. The key is only known right after it is created. */
function ossecBlock(hookUrl: string, apiKey: string): string {
  return [
    "<integration>",
    "  <name>custom-legion</name>",
    `  <hook_url>${hookUrl}</hook_url>`,
    `  <api_key>${apiKey}</api_key>`,
    "  <level>7</level>",
    "  <alert_format>json</alert_format>",
    "</integration>",
  ].join("\n");
}

const INSTALL_COMMANDS = [
  "cp integrations/custom-legion integrations/custom-legion.py /var/ossec/integrations/",
  "chmod 750 /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py",
  "chown root:wazuh /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py",
  "systemctl restart wazuh-manager",
].join("\n");

/**
 * Connect: sign up → connect → protected. Wazuh is set up in three steps
 * (key, one config block, wait for the first event) without needing to know
 * what a webhook is; the technical details are one click away for whoever
 * runs the Wazuh server.
 */
export default function ConnectPage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const c = t.connect;
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [keys, setKeys] = useState<SensorKey[] | null>(null);
  const [catalogue, setCatalogue] = useState<IntegrationInfo[]>([]);
  const [issued, setIssued] = useState<IssuedSensorKey | null>(null);
  const [label, setLabel] = useState("");
  const [open, setOpen] = useState(false);
  const [showTech, setShowTech] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const isAdmin = me?.role === "admin";
  const didOpen = useRef(false);

  const loadKeys = useCallback(async () => {
    try {
      const r = await getSensorKeys();
      setKeys(r.credentials);
      return r.credentials;
    } catch (err) {
      setError(err);
      return null;
    }
  }, []);

  useEffect(() => {
    if (!isLoggedIn()) { router.push("/login"); return; }
    getMe().then((u) => {
      setMe(u);
      if (u.role === "admin") {
        loadKeys().then((list) => {
          // A workspace with nothing connected opens straight into the setup.
          if (list && !list.some((k) => k.status !== "revoked") && !didOpen.current) { didOpen.current = true; setOpen(true); }
        });
      }
    }).catch((err) => {
      if (err instanceof ApiError && err.status === 401) router.push("/login");
      else setError(err);
    });
    getIntegrationCatalogue().then((r) => setCatalogue(r.integrations)).catch(() => {});
  }, [router, loadKeys]);

  const usable = (keys ?? []).filter((k) => k.status === "active" || k.status === "rotating");
  const connected = usable.some((k) => k.last_used_at);

  // Waiting for the first event: check again every few seconds while the setup is open.
  useEffect(() => {
    if (!isAdmin || !open || connected || usable.length === 0) return;
    const timer = setInterval(() => { loadKeys(); }, POLL_MS);
    return () => clearInterval(timer);
  }, [isAdmin, open, connected, usable.length, loadKeys]);

  async function run(fn: () => Promise<void>) {
    setBusy(true); setError(null); setNotice(null);
    try { await fn(); } catch (err) { setError(err); } finally { setBusy(false); }
  }

  const create = () => run(async () => {
    const k = await createSensorKey(label.trim() || "Wazuh"); // i18n-ignore: product name as the default label
    setIssued(k);
    setLabel("");
    await loadKeys();
  });
  const revoke = (id: string) => {
    if (!window.confirm(c.keys.revokeConfirm)) return;
    run(async () => {
      await revokeSensorKey(id);
      if (issued?.id === id) setIssued(null);
      setNotice(c.keys.revoked);
      await loadKeys();
    });
  };
  const test = () => run(async () => {
    await sendTestAlert();
    setNotice(c.test.sent);
  });

  const hook = webhookUrl();
  const block = ossecBlock(hook, issued?.api_key ?? "KEY_ID:SECRET"); // i18n-ignore: placeholder in a config file
  const planned = catalogue.filter((i) => i.plane === "data" && i.status === "planned");

  const step = "rounded-lg border border-line bg-canvas/40 p-3.5";
  const num = "flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-semibold shrink-0";

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-3xl mx-auto space-y-4">
          <header>
            <h1 className="legion-title text-ink flex items-center gap-2"><Plug size={18} /> {c.title}</h1>
            <p className="text-ink-muted text-sm mt-1.5">{c.intro}</p>
          </header>

          {me && !isAdmin && (
            <div className="flex items-start gap-2 text-warning text-xs bg-warning/10 rounded-lg px-3 py-2.5">
              <ShieldAlert size={14} className="shrink-0 mt-0.5" /> {c.adminOnly}
            </div>
          )}
          {error != null && <ErrorNotice error={error} isAdmin={isAdmin} />}
          {notice && (
            <p role="status" className="flex items-center gap-2 text-success text-xs bg-success/10 rounded-lg px-3 py-2.5">
              <CheckCircle2 size={14} /> {notice}
              {notice === c.test.sent && <Link href="/" className="ml-auto font-medium text-brand-bright hover:underline">{t.nav.dashboard}</Link>}
            </p>
          )}

          {/* Wazuh */}
          <section className="rounded-xl border border-line bg-surface">
            <div className="flex items-start gap-3 px-4 py-4">
              <div className="w-9 h-9 rounded-lg bg-brand/15 text-brand-bright flex items-center justify-center shrink-0 font-semibold text-sm">W</div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-ink text-sm font-semibold">Wazuh{/* i18n-ignore: product name */}</h2>
                  {keys && usable.length > 0 && (
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${connected ? "bg-success/15 text-success" : "bg-panel text-ink-faint"}`} data-testid="wazuh-status">
                      {connected ? c.connected : c.waiting}
                    </span>
                  )}
                  {!(keys && usable.length > 0) && <span className="text-[10px] px-1.5 py-0.5 rounded bg-panel text-ink-faint">{c.available}</span>}
                </div>
                <p className="text-ink-muted text-xs mt-1">{c.wazuh.summary}</p>
              </div>
              {isAdmin && (
                <button type="button" onClick={() => setOpen(!open)} className="shrink-0 flex items-center gap-1 text-xs font-medium px-3 py-1.5 rounded-lg border border-line text-ink-muted hover:text-ink" aria-expanded={open}>
                  {open ? c.close : c.setUp} {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                </button>
              )}
            </div>

            {isAdmin && open && (
              <div className="border-t border-line px-4 py-4 space-y-3">
                <div className={step}>
                  <h3 className="flex items-center gap-2 text-ink text-xs font-medium">
                    <span className={`${num} ${issued || usable.length ? "bg-success/20 text-success" : "bg-brand/20 text-brand-bright"}`}>1</span>
                    {c.wazuh.step1.title}
                  </h3>
                  <p className="text-ink-faint text-[11px] mt-1 ml-7">{c.wazuh.step1.body}</p>
                  {!issued && (
                    <div className="flex flex-wrap gap-2 mt-2 ml-7">
                      <input
                        value={label}
                        maxLength={100}
                        onChange={(e) => setLabel(e.target.value)}
                        placeholder={c.wazuh.step1.labelPlaceholder}
                        aria-label={c.wazuh.step1.label}
                        className="flex-1 min-w-[160px] bg-canvas border border-line rounded-md px-2 py-1.5 text-xs text-ink outline-none focus:border-brand-hover"
                      />
                      <button type="button" disabled={busy} onClick={create} className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-md bg-brand hover:bg-brand-hover text-white disabled:opacity-60">
                        {busy ? <Loader2 size={12} className="animate-spin" /> : <KeyRound size={12} />} {c.wazuh.step1.action}
                      </button>
                    </div>
                  )}
                </div>

                <div className={step}>
                  <h3 className="flex items-center gap-2 text-ink text-xs font-medium">
                    <span className={`${num} bg-brand/20 text-brand-bright`}>2</span>
                    {c.wazuh.step2.title}
                  </h3>
                  <ol className="text-ink-muted text-[11px] mt-1 ml-7 space-y-1.5 list-decimal list-inside">
                    <li>{c.wazuh.step2.files}</li>
                    <li>{c.wazuh.step2.conf}</li>
                  </ol>
                  <div className="ml-7 mt-2">
                    <div className="flex justify-end mb-1"><CopyButton value={block} /></div>
                    <pre className="text-[11px] leading-relaxed text-ink-soft bg-canvas border border-line rounded-md p-2.5 overflow-x-auto" data-testid="ossec-block">{block}</pre>
                    <p className={`text-[11px] mt-1.5 ${issued ? "text-warning" : "text-ink-faint"}`}>
                      {issued ? c.wazuh.step2.keyOnce : c.wazuh.step2.keyHidden}
                    </p>
                  </div>
                </div>

                <div className={step}>
                  <h3 className="flex items-center gap-2 text-ink text-xs font-medium">
                    <span className={`${num} ${connected ? "bg-success/20 text-success" : "bg-brand/20 text-brand-bright"}`}>3</span>
                    {c.wazuh.step3.title}
                  </h3>
                  <p className={`flex items-center gap-1.5 text-xs mt-1.5 ml-7 ${connected ? "text-success" : "text-ink-muted"}`} aria-live="polite">
                    {connected ? <CheckCircle2 size={13} /> : <Loader2 size={13} className="animate-spin" />}
                    {connected ? c.wazuh.step3.connected : c.wazuh.step3.waiting}
                  </p>
                  {!connected && <p className="text-ink-faint text-[11px] mt-1 ml-7">{c.wazuh.step3.hint}</p>}
                  <div className="ml-7 mt-2">
                    <button type="button" disabled={busy} onClick={test} className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-md border border-line text-ink-muted hover:text-ink disabled:opacity-60">
                      <Send size={12} /> {c.test.action}
                    </button>
                    <p className="text-ink-faint text-[10px] mt-1">{c.test.hint}</p>
                  </div>
                </div>

                <div>
                  <button type="button" onClick={() => setShowTech(!showTech)} className="flex items-center gap-1 text-[11px] text-ink-faint hover:text-ink-muted" aria-expanded={showTech}>
                    {showTech ? <ChevronDown size={12} /> : <ChevronRight size={12} />} {c.wazuh.technical}
                  </button>
                  {showTech && (
                    <div className="mt-2 space-y-2 text-[11px] text-ink-muted">
                      <p>{c.wazuh.technicalItems.endpoint}: <code className="text-ink-soft break-all">{hook}</code></p>
                      <div>
                        <div className="flex items-center justify-between mb-1"><span>{c.wazuh.technicalItems.commands}</span><CopyButton value={INSTALL_COMMANDS} /></div>
                        <pre className="text-[11px] text-ink-soft bg-canvas border border-line rounded-md p-2.5 overflow-x-auto">{INSTALL_COMMANDS}</pre>
                      </div>
                      <p>{c.wazuh.technicalItems.level}</p>
                      <p>{c.wazuh.technicalItems.docs}</p>
                    </div>
                  )}
                </div>

                {keys && keys.length > 0 && (
                  <div>
                    <h3 className="text-ink-muted text-[11px] uppercase tracking-wide mb-1.5">{c.keys.title}</h3>
                    <ul className="divide-y divide-line border border-line rounded-lg">
                      {keys.map((k) => (
                        <li key={k.id} className="flex items-center gap-3 px-3 py-2 text-xs">
                          <div className="min-w-0 flex-1">
                            <p className="text-ink truncate">{k.label}</p>
                            <p className="text-ink-faint text-[11px]">
                              {c.keys.status[k.status] ?? k.status} · {k.last_used_at ? c.keys.lastUsed(timeAgo(k.last_used_at, locale)) : c.keys.neverUsed}
                            </p>
                          </div>
                          {(k.status === "active" || k.status === "rotating") && (
                            <button type="button" disabled={busy} onClick={() => revoke(k.id)} className="flex items-center gap-1 text-[11px] text-ink-faint hover:text-critical disabled:opacity-60">
                              <Trash2 size={11} /> {c.keys.revoke}
                            </button>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* AI agents: MCP servers and agent-to-agent calls are protected there. */}
          <section className="rounded-xl border border-line bg-surface flex items-start gap-3 px-4 py-4">
            <div className="w-9 h-9 rounded-lg bg-brand/15 text-brand-bright flex items-center justify-center shrink-0"><BrainCircuit size={16} /></div>
            <div className="min-w-0 flex-1">
              <h2 className="text-ink text-sm font-semibold">{c.agentsCard.title}</h2>
              <p className="text-ink-muted text-xs mt-1">{c.agentsCard.body}</p>
            </div>
            <Link href="/agents" className="shrink-0 text-xs font-medium px-3 py-1.5 rounded-lg border border-line text-ink-muted hover:text-ink">{c.agentsCard.action}</Link>
          </section>

          {planned.length > 0 && (
            <section>
              <h2 className="text-ink-muted text-[11px] uppercase tracking-wide mb-2">{c.soon}</h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {planned.map((i) => (
                  <div key={i.kind} className="rounded-lg border border-line bg-surface/60 px-3 py-2.5 text-xs text-ink-faint">
                    <p className="text-ink-muted">{i.displayName}</p>
                    <p className="text-[10px]">{c.soon}</p>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
