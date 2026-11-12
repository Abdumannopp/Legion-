"use client";

import { useEffect, useState } from "react";
import { ExternalLink, Send } from "lucide-react";
import { AlertDelivery, getAlertDeliveries } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/** Where this alert was sent (Slack, Jira…) and which ticket it became. Renders nothing when it was sent nowhere. */
export default function AlertDeliveries({ alertId }: { alertId: string }) {
  const { t } = useLanguage();
  const m = t.connections.deliveries;
  const [list, setList] = useState<AlertDelivery[]>([]);
  useEffect(() => { getAlertDeliveries(alertId).then((r) => setList(r.deliveries)).catch(() => setList([])); }, [alertId]);
  if (!list.length) return null;
  return (
    <section className="mb-4 lg-surface px-4 py-3" data-testid="alert-deliveries">
      <h3 className="text-ink text-xs font-semibold flex items-center gap-1.5"><Send size={12} />{m.title}</h3>
      <ul className="mt-1.5 space-y-1">
        {list.map((d, i) => (
          <li key={i} className="text-xs text-ink-muted flex flex-wrap items-center gap-2">
            <span className="text-ink">{d.connection}</span>
            <span>· {m.status[d.status]}</span>
            {d.ticket && <a href={d.ticket.url} target="_blank" rel="noopener noreferrer" className="text-brand-bright flex items-center gap-1">{m.ticket(d.ticket.key)}<ExternalLink size={11} /></a>}
            {d.status === "dead" && d.last_error && <span className="text-danger break-words">{d.last_error}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}
