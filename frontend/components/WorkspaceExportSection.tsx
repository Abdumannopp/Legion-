"use client";

import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { ApiError, downloadWorkspaceExport } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/** Administrators can take everything the workspace holds with them. */
export default function WorkspaceExportSection({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useLanguage();
  const d = t.settings.dataExport;
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  if (!isAdmin) return null;

  async function run() {
    setBusy(true);
    setMessage(null);
    try {
      const { blob, filename } = await downloadWorkspaceExport();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMessage(d.done);
    } catch (err) {
      setMessage(err instanceof ApiError && err.status === 429 ? d.tooMany : d.failed);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="lg-surface p-5" data-testid="workspace-export">
      <h3 className="text-ink font-medium text-sm">{d.title}</h3>
      <p className="text-ink-muted text-xs mt-1.5 leading-relaxed">{d.hint}</p>
      <button onClick={run} disabled={busy}
        className="mt-4 inline-flex items-center gap-2 rounded-lg border border-line-strong px-3 py-2 text-sm text-ink-soft hover:text-ink hover:border-brand-hover disabled:opacity-50">
        {busy ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
        {busy ? d.preparing : d.button}
      </button>
      {message && <p className="text-ink-muted text-xs mt-2" role="status">{message}</p>}
    </div>
  );
}
