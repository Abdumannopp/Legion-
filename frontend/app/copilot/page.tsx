"use client";

import AiBadge from "@/components/AiBadge";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Bot, Send, Loader2, User, Sparkles } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import { askCopilot, isLoggedIn, ApiError, ChatMessage } from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/** A conversation turn as shown. `aiGenerated` is display-only: it is not sent
 *  back as history. */
type Turn = ChatMessage & { aiGenerated?: boolean };

function MessageBubble({ message }: { message: Turn }) {
  const isUser = message.role === "user";
  const lines = message.content.split("\n").filter((l) => l.trim());

  return (
    <div className={`flex gap-3 ${isUser ? "flex-row-reverse" : ""}`}>
      <div
        className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
          isUser ? "bg-line" : "bg-brand/15"
        }`}
      >
        {isUser ? (
          <User size={14} color={palette.inkMuted} />
        ) : (
          <Bot size={14} color={palette.brandBright} />
        )}
      </div>
      <div
        className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
          isUser
            ? "bg-brand text-white rounded-tr-sm"
            : "bg-surface border border-line text-ink-soft rounded-tl-sm"
        }`}
      >
        {!isUser && message.aiGenerated !== undefined && (
          <div className="mb-1.5"><AiBadge aiGenerated={message.aiGenerated} /></div>
        )}
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
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
    }
  }, [router]);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
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
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen">
        <div className="border-b border-line px-6 py-4 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-brand/15 flex items-center justify-center">
            <Sparkles size={16} color={palette.brandBright} />
          </div>
          <div>
            <h1 className="text-ink font-semibold text-sm leading-none">
              {t.copilot.title}
            </h1>
            <p className="text-ink-faint text-[11px] mt-1">
              {t.copilot.subtitle}
            </p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-5">
          <div className="max-w-2xl mx-auto space-y-5">
            {messages.map((m, i) => (
              <MessageBubble key={i} message={m} />
            ))}
            {sending && (
              <div className="flex gap-3">
                <div className="w-7 h-7 rounded-lg bg-brand/15 flex items-center justify-center shrink-0">
                  <Bot size={14} color={palette.brandBright} />
                </div>
                <div className="bg-surface border border-line rounded-2xl rounded-tl-sm px-4 py-2.5">
                  <Loader2 size={14} className="animate-spin text-ink-faint" />
                </div>
              </div>
            )}
            {error && (
              <div className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2.5 max-w-md">
                {error}
              </div>
            )}
            <div ref={scrollRef} />
          </div>
        </div>

        {messages.length <= 1 && (
          <div className="px-6 pb-3">
            <div className="max-w-2xl mx-auto flex flex-wrap gap-2">
              {t.copilot.suggestions.map((q) => (
                <button
                  key={q}
                  onClick={() => send(q)}
                  className="text-xs text-ink-muted border border-line rounded-full px-3 py-1.5 hover:border-brand-hover/40 hover:text-ink transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="border-t border-line p-4">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              send(input);
            }}
            className="max-w-2xl mx-auto flex items-center gap-2"
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={t.copilot.inputPlaceholder}
              className="flex-1 bg-surface border border-line rounded-xl px-4 py-2.5 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
            />
            <button
              type="submit"
              disabled={sending || !input.trim()}
              className="w-10 h-10 flex items-center justify-center rounded-xl bg-brand hover:bg-brand-hover disabled:opacity-40 transition-colors"
            >
              <Send size={16} color="white" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
