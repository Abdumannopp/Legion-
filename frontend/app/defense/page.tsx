"use client";

/**
 * Defense: attack campaigns (correlated alerts), the automatic response that
 * blocks attackers through the Wazuh manager, and the current blocklist.
 * Everyone in the workspace sees it; only administrators change it.
 */
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Ban, Loader2, Radar, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import ErrorNotice from "@/components/ErrorNotice";
import {
  ApiError, AttackCampaign, AutoResponseSettings, IpBlock,
  blockAddress, getAutoResponse, getBlocks, getCampaigns, getMe, isLoggedIn, unblockAddress, updateAutoResponse,
} from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { formatDateTime, timeAgo } from "@/lib/i18n/format";

const MINUTES = [15, 30, 60, 240, 1440, 10080];
const card = "bg-surface border border-line rounded-2xl p-5";
const input = "w-full bg-canvas border border-line rounded-lg px-3 py-2 text-sm text-ink outline-none focus:border-brand-hover";

export default function DefensePage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const d = t.defense;
  const [isAdmin, setIsAdmin] = useState(false);
  const [settings, setSettings] = useState<AutoResponseSettings | null>(null);
  const [draft, setDraft] = useState<AutoResponseSettings | null>(null);
  const [campaigns, setCampaigns] = useState<AttackCampaign[]>([]);
  const [blocks, setBlocks] = useState<IpBlock[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [newIp, setNewIp] = useState("");
  const [newReason, setNewReason] = useState("");

  const load = useCallback(async () => {
    try {
      const [me, s, c, b] = await Promise.all([getMe(), getAutoResponse(), getCampaigns(), getBlocks(true)]);
      setIsAdmin(me.role === "admin");
      setSettings(s); setDraft(s); setCampaigns(c); setBlocks(b);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { router.push("/login"); return; }
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    if (!isLoggedIn()) { router.push("/login"); return; }
    load();
    // Campaigns and blocks change while an attack is under way.
    const timer = setInterval(() => { getCampaigns().then(setCampaigns).catch(() => {}); getBlocks(true).then(setBlocks).catch(() => {}); }, 15_000);
    return () => clearInterval(timer);
  }, [load, router]);

  async function save() {
    if (!draft) return;
    setSaving(true); setError(null); setSaved(false);
    try {
      const next = await updateAutoResponse(draft);
      setSettings(next); setDraft(next); setSaved(true);
    } catch (err) { setError(err); } finally { setSaving(false); }
  }

  async function unblock(ip: string) {
    if (!window.confirm(d.blocks.confirmUnblock(ip))) return;
    setError(null);
    try { await unblockAddress(ip); setBlocks(await getBlocks(true)); } catch (err) { setError(err); }
  }

  async function addBlock(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await blockAddress(newIp, newReason);
      setNewIp(""); setNewReason("");
      setBlocks(await getBlocks(true));
    } catch (err) { setError(err); }
  }

  const changed = draft && settings && (draft.mode !== settings.mode || draft.minutes !== settings.minutes || draft.allowlist !== settings.allowlist);

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-5xl mx-auto space-y-5">
          <div>
            <h1 className="legion-title text-ink flex items-center gap-2">
              <ShieldAlert size={20} color={palette.brandBright} />
              {d.title}
            </h1>
            <p className="text-ink-muted text-sm mt-2 leading-relaxed max-w-3xl">{d.intro}</p>
          </div>

          {error != null && <ErrorNotice error={error} />}

          {loading ? (
            <div className="flex justify-center py-16"><Loader2 size={18} className="animate-spin text-ink-faint" /></div>
          ) : (
            <>
              {/* Automatic response */}
              <section className={card}>
                <h2 className="text-ink font-medium flex items-center gap-2 mb-3"><Zap size={16} color={palette.warning} />{d.auto.title}</h2>
                {draft && (
                  <div className="space-y-4">
                    <div className="grid sm:grid-cols-2 gap-2">
                      {(["off", "auto"] as const).map((mode) => (
                        <label key={mode} className={`flex items-start gap-2 border rounded-lg p-3 text-sm ${draft.mode === mode ? "border-brand-hover bg-brand/10 text-ink" : "border-line text-ink-muted"} ${isAdmin ? "cursor-pointer" : "opacity-80"}`}>
                          <input type="radio" name="mode" value={mode} disabled={!isAdmin} checked={draft.mode === mode}
                            onChange={() => { setDraft({ ...draft, mode }); setSaved(false); }} className="mt-1 accent-brand" />
                          <span>
                            <span className="block font-medium">{mode === "off" ? d.auto.off : d.auto.on}</span>
                            <span className="block text-xs text-ink-faint mt-1 leading-relaxed">{mode === "off" ? d.auto.offHelp : d.auto.onHelp}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                    <div className="grid sm:grid-cols-3 gap-3">
                      <div>
                        <label className="text-ink-muted text-xs mb-1.5 block">{d.auto.minutes}</label>
                        <select disabled={!isAdmin} value={draft.minutes} onChange={(e) => { setDraft({ ...draft, minutes: Number(e.target.value) }); setSaved(false); }} className={input}>
                          {[...new Set([...MINUTES, draft.minutes])].sort((a, b) => a - b).map((m) => <option key={m} value={m}>{d.auto.minutesOption(m)}</option>)}
                        </select>
                      </div>
                      <div className="sm:col-span-2">
                        <label className="text-ink-muted text-xs mb-1.5 block">{d.auto.allowlist}</label>
                        <input disabled={!isAdmin} value={draft.allowlist} onChange={(e) => { setDraft({ ...draft, allowlist: e.target.value }); setSaved(false); }} className={`${input} font-mono`} />
                        <p className="text-ink-faint text-[11px] mt-1 leading-relaxed">{d.auto.allowlistHelp}</p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                      {isAdmin ? (
                        <button onClick={save} disabled={!changed || saving} className="flex items-center gap-2 bg-brand hover:bg-brand-hover disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg">
                          {saving && <Loader2 size={14} className="animate-spin" />}{d.auto.save}
                        </button>
                      ) : (
                        <span className="text-xs text-ink-faint">{d.auto.adminOnly}</span>
                      )}
                      {saved && <span className="text-xs text-success flex items-center gap-1"><ShieldCheck size={13} />{d.auto.saved}</span>}
                    </div>
                    <p className="text-ink-faint text-[11px] leading-relaxed border-t border-line pt-3">{d.auto.wazuhNote}</p>
                  </div>
                )}
              </section>

              {/* Campaigns */}
              <section className={card}>
                <h2 className="text-ink font-medium flex items-center gap-2 mb-3"><Radar size={16} color={palette.critical} />{d.campaigns.title}</h2>
                {campaigns.length === 0 ? (
                  <p className="text-ink-faint text-sm leading-relaxed">{d.campaigns.empty}</p>
                ) : (
                  <ul className="divide-y divide-line">
                    {campaigns.map((c) => (
                      <li key={c.id} className="py-3 flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-ink text-sm font-medium">{d.campaigns.rule[c.rule] ?? c.rule}</span>
                            <span className="font-mono text-xs text-ink-muted">{c.subject}</span>
                            <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${c.status === "active" ? "bg-critical/15 text-critical" : "bg-line text-ink-faint"}`}>
                              {c.status === "active" ? d.campaigns.active : d.campaigns.ended}
                            </span>
                          </div>
                          <div className="text-xs text-ink-faint mt-1 space-x-3">
                            <span>{d.campaigns.alerts(c.alert_count)}</span>
                            {c.techniques.length > 0 && <span>{d.campaigns.techniques}: <span className="font-mono">{c.techniques.join(", ")}</span></span>}
                            {c.rule === "swarm"
                              ? <span>{d.campaigns.sources}: {c.sources.length}</span>
                              : c.targets.length > 0 && <span>{d.campaigns.targets}: {c.targets.slice(0, 5).join(", ")}{c.targets.length > 5 ? "…" : ""}</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-xs text-ink-faint" title={formatDateTime(c.last_seen, locale)}>{timeAgo(c.last_seen, locale)}</span>
                          {c.alert_id && <Link href={`/incident/${c.alert_id}`} className="text-xs text-brand-bright hover:text-ink">{d.campaigns.open} →</Link>}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {/* Blocklist */}
              <section className={card}>
                <h2 className="text-ink font-medium flex items-center gap-2 mb-3"><Ban size={16} color={palette.warning} />{d.blocks.title}</h2>
                {blocks.length === 0 ? (
                  <p className="text-ink-faint text-sm">{d.blocks.empty}</p>
                ) : (
                  <ul className="divide-y divide-line">
                    {blocks.map((b) => (
                      <li key={b.id} className="py-2.5 flex flex-wrap items-center gap-3">
                        <span className="font-mono text-sm text-ink">{b.ip}</span>
                        <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${b.automatic ? "bg-warning/15 text-warning" : "bg-line text-ink-muted"}`}>
                          {b.automatic ? d.blocks.automatic : d.blocks.manual}
                        </span>
                        <span className="text-xs text-ink-faint flex-1 min-w-[160px] truncate" title={b.reason}>{b.reason}</span>
                        <span className="text-xs text-ink-faint">{d.blocks.until} {formatDateTime(b.expires_at, locale)}</span>
                        {isAdmin && (
                          <button onClick={() => unblock(b.ip)} className="text-xs text-ink-muted hover:text-ink border border-line rounded-md px-2 py-1">{d.blocks.unblock}</button>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                {isAdmin && (
                  <form onSubmit={addBlock} className="mt-4 pt-4 border-t border-line grid sm:grid-cols-[1fr_1.5fr_auto] gap-2">
                    <input required value={newIp} onChange={(e) => setNewIp(e.target.value)} placeholder={d.blocks.addPlaceholder} className={`${input} font-mono`} aria-label={d.blocks.addTitle} />
                    <input value={newReason} onChange={(e) => setNewReason(e.target.value)} placeholder={d.blocks.reasonPlaceholder} maxLength={500} className={input} />
                    <button type="submit" className="bg-critical/90 hover:bg-critical text-white text-sm font-medium px-4 py-2 rounded-lg">{d.blocks.add}</button>
                  </form>
                )}
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
