"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Search, Loader2, Monitor, Wifi, WifiOff } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import { Asset, getAssets, isLoggedIn, ApiError } from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const RISK_COLOR: Record<Asset["risk"], string> = {
  critical: palette.critical,
  high: palette.critical,
  medium: palette.warning,
  low: palette.success,
};

const OS_ICON: Record<string, string> = {
  Linux: "🐧",
  Windows: "🪟",
  macOS: "🍎",
};

export default function AssetsPage() {
  const router = useRouter();
  const { t } = useLanguage();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await getAssets({
        risk: riskFilter === "all" ? undefined : riskFilter,
        q: query || undefined,
      });
      setAssets(data);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err instanceof ApiError ? err.message : t.assets.loadError);
    } finally {
      setLoading(false);
    }
  }, [riskFilter, query, router, t]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    load();
  }, [load, router]);

  const riskCounts = {
    critical: assets.filter((a) => a.risk === "critical").length,
    high: assets.filter((a) => a.risk === "high").length,
    medium: assets.filter((a) => a.risk === "medium").length,
    low: assets.filter((a) => a.risk === "low").length,
  };
  const onlineCount = assets.filter((a) => a.online).length;

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-4xl mx-auto">
          <div className="mb-6">
            <h1 className="legion-title text-ink flex items-center gap-2">
              <Monitor size={20} color={palette.brandBright} />
              {t.assets.title}
            </h1>
            <p className="text-ink-faint text-[11px] tracking-[0.1em] uppercase mt-1.5">
              {t.assets.summary(assets.length, onlineCount)}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 mb-4">
            <div className="relative flex-1 min-w-[180px]">
              <Search
                size={15}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint"
              />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t.assets.searchPlaceholder}
                className="w-full bg-surface border border-line rounded-lg pl-9 pr-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
              />
            </div>
            {(["all", "critical", "high", "medium", "low"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setRiskFilter(f)}
                className={`text-xs font-medium px-3 py-2 rounded-lg border transition-colors whitespace-nowrap ${
                  riskFilter === f
                    ? "border-brand-hover text-brand-bright bg-brand/10"
                    : "border-line text-ink-faint hover:text-ink-muted"
                }`}
              >
                {f === "all" ? t.common.all : t.common.risk[f]}{" "}
                {f === "all" ? assets.length : riskCounts[f]}
              </button>
            ))}
          </div>

          {error && (
            <div className="mb-4 text-critical text-xs bg-critical/10 rounded-lg px-3 py-2.5">
              {error}
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <Loader2 size={20} className="animate-spin" />
            </div>
          ) : (
            <div className="rounded-xl border border-line bg-surface overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left">
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                      {t.assets.columns.device}
                    </th>
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                      {t.assets.columns.status}
                    </th>
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                      {t.assets.columns.risk}
                    </th>
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                      {t.assets.columns.os}
                    </th>
                    <th className="hidden sm:table-cell px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                      {t.assets.columns.ip}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr
                      key={asset.id}
                      className="border-b border-line last:border-b-0 hover:bg-panel transition-colors"
                    >
                      <td className="px-4 py-3">
                        <p className="text-ink font-medium">{asset.name}</p>
                        <p className="text-ink-faint text-[11px] font-mono">{asset.id}</p>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <span
                            className="w-2 h-2 rounded-full"
                            style={{
                              backgroundColor: asset.online ? palette.success : palette.inkFaint,
                            }}
                          />
                          <span className="text-ink-muted text-xs flex items-center gap-1">
                            {asset.online ? (
                              <>
                                <Wifi size={11} /> {t.assets.online}
                              </>
                            ) : (
                              <>
                                <WifiOff size={11} /> {t.assets.offline}
                              </>
                            )}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="text-xs font-medium px-2 py-0.5 rounded"
                          style={{
                            color: RISK_COLOR[asset.risk],
                            backgroundColor: `${RISK_COLOR[asset.risk]}1A`,
                          }}
                        >
                          {t.common.risk[asset.risk]}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-ink-muted">
                        <span className="mr-1.5">{OS_ICON[asset.os] || "💻"}</span>
                        {asset.os}
                      </td>
                      <td className="hidden sm:table-cell px-4 py-3 text-ink-faint font-mono text-xs">
                        {asset.ip_address || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {assets.length === 0 && (
                <div className="text-center py-12 text-ink-faint text-sm">
                  {t.assets.empty}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
