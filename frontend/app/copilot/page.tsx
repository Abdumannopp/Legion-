"use client";

import AiBadge from "@/components/AiBadge";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Send, Loader2, User, Sparkles, Plus, ShieldCheck, ChevronRight } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import { askCopilot, getOverview, isLoggedIn, ApiError, ChatMessage, type Overview } from "@/lib/api";
import { palette, severityColor } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { timeAgo } from "@/lib/i18n/format";

/** A conversation turn as shown. `aiGenerated` is display-only: it is not sent
 *  back as history. */
type Turn = ChatMessage & { aiGenerated?: boolean };

function MessageBubble({ message }: { message: Turn }) {
  const { t } = useLanguage();
  const isUser = message.role === "user";
  const lines = message.content.split("\n").filter((l) => l.trim());

  if (isUser) {
    return (
      <div className="flex gap-3 flex-row-reverse lg-enter">
        <div className="w-8 h-8 rounded-full bg-surface-raised border border-line flex items-center justify-center shrink-0" aria-hidden>
          <User size={14} color={palette.inkMuted} />
        </div>
        <div className="max-w-[85%] rounded-2xl rounded-tr-md px-4 py-2.5 text-sm leading-relaxed bg-brand/25 border border-brand-hover/40 text-ink">
          <span className="sr-only">{t.copilot.you}: </span>
          {message.content}
        </div>
      </div>
    );
  }
  return (
    <div className="lg-surface-soft p-4 lg-enter">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-7 h-7 rounded-lg bg-brand/20 border border-brand-hover/30 flex items-center justify-center" aria-hidden>
          <Sparkles size={14} color={palette.brandBright} />
        </span>
        <span className="text-ink text-sm font-semibold">{t.copilot.assistantName}</span>
        {message.aiGenerated !== undefined && <span className="ml-auto"><AiBadge aiGenerated={message.aiGenerated} /></span>}
      </div>
      <div className="text-sm leading-relaxed text-ink-soft">
        {lines.map((line, i) =>
          line.trim().startsWith("-") ? (
            <div key={i} className="flex gap-1.5 pl-1 mt-1 first:mt-0">
              <span className="text-brand-bright">•</span>
              <span>{line.replace(/^-\s*/, "")}</span>
            </div>
          ) : (
            <p key={i} className={i > 0 ? "mt-1.5" : ""}>
              {line}
            </p>
          )
        )}
      </div>
    </div>
  );
}

/** The right rail: real open alerts from GET /overview, and the rule that Copilot never acts. */
function ContextRail({ overview, onAsk }: { overview: Overview | null; onAsk: (text: string) => void }) {
  const { t, locale } = useLanguage();
  const top = overview?.threats.top ?? [];
  return (
    <aside className="lg-surface p-5 space-y-5 lg:sticky lg:top-6" aria-labelledby="ctx-title">
      <div>
        <h2 id="ctx-title" className="text-ink text-sm font-semibold">{t.copilot.contextTitle}</h2>
        <p className="lg-eyebrow mt-1">{t.copilot.contextSubtitle}</p>
      </div>
      <div>
        <p className="lg-eyebrow mb-2">{t.copilot.relatedAlerts}</p>
        {top.length === 0 ? (
          <p className="text-ink-faint text-xs">{t.copilot.noRelated}</p>
        ) : (
          <ul className="space-y-2">
            {top.slice(0, 4).map((a) => (
              <li key={a.id} className="lg-surface-soft p-3">
                <div className="flex items-start gap-2">
                  <span className="w-2 h-2 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: severityColor[a.severity] }} aria-hidden />
                  <div className="min-w-0 flex-1">
                    <Link href={`/incident/${a.id}`} className="text-ink text-xs font-medium hover:text-brand-bright line-clamp-2">{a.title}</Link>
                    <p className="text-ink-faint text-[11px] mt-0.5">{t.common.severity[a.severity]} · {timeAgo(a.created_at, locale)}</p>
                    <button onClick={() => onAsk(t.copilot.askAbout(a.title))} className="mt-1.5 text-[11px] text-brand-bright hover:underline inline-flex items-center gap-1">
                      <Sparkles size={11} />{t.dashboard.alert.askOracle}<ChevronRight size={11} />
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="rounded-xl border border-brand-hover/30 bg-brand/10 p-3.5">
        <p className="flex items-center gap-2 text-ink text-xs font-semibold"><ShieldCheck size={14} color={palette.brandBright} />{t.copilot.approvalTitle}</p>
        <p className="text-ink-muted text-[11px] mt-1.5 leading-relaxed">{t.copilot.approvalBody}</p>
      </div>
    </aside>
  );
}

export default function CopilotPage() {
  const router = useRouter();
  const { t } = useLanguage();
  // The greeting is not kept in state so it follows the selected language;
  // it still leads the conversation (and the history sent to the server).
  const greeting: ChatMessage = { role: "assistant", content: t.copilot.greeting };
  const [conversation, setConversation] = useState<Turn[]>([]);
  const messages = [greeting, ...conversation];
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    getOverview().then(setOverview).catch(() => { /* the rail is optional */ });
  }, [router]);

  useEffect(() => {
    if (conversation.length || sending) scrollRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [conversation, sending]);

  async function send(text: string) {
    if (!text.trim() || sending) return;
    setError(null);
    const userMsg: ChatMessage = { role: "user", content: text };
    setConversation((prev) => [...prev, userMsg]);
    setInput("");
    setSending(true);

    try {
      const { reply, ai_generated } = await askCopilot(text, messages.map(({ role, content }) => ({ role, content })));
      setConversation((prev) => [...prev, { role: "assistant", content: reply, aiGenerated: ai_generated === true }]);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(
        err instanceof ApiError ? err.message : t.copilot.error
      );
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="flex min-h-screen lg-app-bg">
      <Sidebar />
      <div className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8">
        <div className="max-w-6xl mx-auto">
          <div className="flex items-start justify-between gap-4 flex-wrap mb-5">
            <div>
              <h1 className="text-ink font-semibold tracking-tight text-2xl sm:text-[28px] leading-tight">{t.copilot.title}</h1>
              <p className="text-ink-muted text-sm mt-1">{t.copilot.subtitle}</p>
            </div>
            {conversation.length > 0 && (
              <button onClick={() => { setConversation([]); setError(null); inputRef.current?.focus(); }} className="lg-button-secondary">
                <Plus size={15} />{t.copilot.newConversation}
              </button>
            )}
          </div>

          <div className="grid lg:grid-cols-[minmax(0,1fr)_320px] gap-5 items-start">
            <section className="lg-surface flex flex-col min-h-[60vh]" aria-label={t.copilot.title}>
              <div className="flex items-center gap-3 px-5 py-4 border-b border-line/70">
                <span className="w-10 h-10 rounded-xl bg-brand/20 border border-brand-hover/30 flex items-center justify-center" aria-hidden>
                  <Sparkles size={18} color={palette.brandBright} />
                </span>
                <div>
                  <p className="text-ink text-sm font-semibold">{t.copilot.assistantName}</p>
                  <p className="lg-eyebrow mt-0.5">{t.copilot.assistantRole}</p>
                </div>
              </div>

              <div className="flex-1 px-5 py-5 space-y-4" aria-live="polite">
                {conversation.length === 0 ? (
                  <div className="lg-enter">
                    <h2 className="text-ink text-lg font-semibold">{t.copilot.hello}</h2>
                    <p className="text-ink-muted text-sm mt-1">{t.copilot.helloBody}</p>
                    <p className="text-ink-soft text-sm mt-4 leading-relaxed">{greeting.content}</p>
                    <div className="grid sm:grid-cols-3 gap-3 mt-5">
                      {t.copilot.suggestions.map((q, i) => (
                        <button key={q} onClick={() => send(q)} className="lg-surface-soft lg-interactive text-left p-3.5">
                          <span className="flex items-center gap-2 text-ink text-sm font-medium">
                            <Plus size={14} color={palette.brandBright} />{t.copilot.suggestionTitles[i] ?? q}
                          </span>
                          <span className="block text-ink-faint text-xs mt-1.5">{q}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  conversation.map((m, i) => <MessageBubble key={i} message={m} />)
                )}
                {sending && (
                  <div className="lg-surface-soft p-4 flex items-center gap-2 text-ink-faint text-sm" role="status">
                    <Loader2 size={14} className="animate-spin" />{t.dashboard.alert.oracleThinking}
                  </div>
                )}
                {error && (
                  <div className="text-critical text-xs bg-critical/10 border border-critical/20 rounded-xl px-3 py-2.5" role="alert">
                    {error}
                  </div>
                )}
                <div ref={scrollRef} />
              </div>

              <div className="px-5 pb-5">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    send(input);
                  }}
                  className="flex items-end gap-2 rounded-2xl border border-line bg-canvas/60 p-2 focus-within:border-brand-hover/60 focus-within:shadow-violet transition-shadow"
                >
                  <label htmlFor="copilot-input" className="sr-only">{t.copilot.inputPlaceholder}</label>
                  <textarea
                    id="copilot-input"
                    ref={inputRef}
                    rows={1}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }}
                    placeholder={t.copilot.inputPlaceholder}
                    className="flex-1 resize-none bg-transparent px-3 py-2 text-sm text-ink placeholder:text-ink-faint outline-none max-h-40"
                  />
                  <button
                    type="submit"
                    disabled={sending || !input.trim()}
                    aria-label={t.copilot.inputPlaceholder}
                    className="w-10 h-10 shrink-0 flex items-center justify-center rounded-full bg-gradient-to-br from-brand-hover to-brand-deep hover:brightness-110 disabled:opacity-40 transition"
                  >
                    <Send size={16} color="white" />
                  </button>
                </form>
                <p className="text-ink-faint text-[11px] mt-2 px-1">{t.copilot.disclaimer}</p>
              </div>
            </section>

            <ContextRail overview={overview} onAsk={(text) => { setInput(text); inputRef.current?.focus(); }} />
          </div>
        </div>
      </div>
    </div>
  );
}
