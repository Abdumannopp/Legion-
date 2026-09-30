"use client";

import AiSettingsSection from "@/components/AiSettingsSection";
import RegionalSettingsSection from "@/components/RegionalSettingsSection";
import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Settings as SettingsIcon,
  Loader2,
  User,
  Bell,
  Users,
  History,
  Send,
  Save,
  ShieldAlert,
  UserPlus,
  MailWarning,
  KeyRound,
  Ban,
} from "lucide-react";
import Sidebar from "@/components/Sidebar";
import AccessBanner from "@/components/AccessBanner";
import MfaSection from "@/components/MfaSection";
import {
  CurrentUser,
  TeamUser,
  AuditLogEntry,
  NotificationSettings,
  getMe,
  getUsers,
  updateUserRole,
  inviteUser,
  resendInvite,
  deactivateUser,
  changePassword,
  getAuditLogs,
  getNotificationSettings,
  updateNotificationSettings,
  sendTestNotification,
  isLoggedIn,
  ApiError,
} from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { LOCALES, type Locale } from "@/lib/i18n/core";
import { formatDateTime } from "@/lib/i18n/format";

type Tab = "profile" | "notifications" | "team" | "audit";

// Labels come from t.settings.tabs[id].
const TABS: { id: Tab; Icon: typeof User; adminOnly: boolean }[] = [
  { id: "profile", Icon: User, adminOnly: false },
  { id: "notifications", Icon: Bell, adminOnly: true },
  { id: "team", Icon: Users, adminOnly: true },
  { id: "audit", Icon: History, adminOnly: true },
];

const ROLE_COLOR: Record<TeamUser["role"], string> = {
  admin: palette.brandBright,
  analyst: palette.warning,
  viewer: palette.inkFaint,
};

function AdminOnlyNotice() {
  const { t } = useLanguage();
  return (
    <div className="flex items-center gap-2 text-warning text-xs bg-warning/10 rounded-lg px-3 py-2.5">
      <ShieldAlert size={14} className="shrink-0" />
      {t.settings.adminOnly}
    </div>
  );
}

export default function SettingsPage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const [tab, setTab] = useState<Tab>("profile");
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Notifications tab state
  const [notifSettings, setNotifSettings] = useState<NotificationSettings | null>(null);
  const [notifEmail, setNotifEmail] = useState("");
  const [notifLocale, setNotifLocale] = useState<Locale>("en");
  const [notifSaving, setNotifSaving] = useState(false);
  const [notifTesting, setNotifTesting] = useState(false);
  const [notifMessage, setNotifMessage] = useState<string | null>(null);

  // Team tab state
  const [users, setUsers] = useState<TeamUser[]>([]);
  const [teamBusyId, setTeamBusyId] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamUser["role"]>("analyst");
  const [inviting, setInviting] = useState(false);
  const [inviteNotice, setInviteNotice] = useState<string | null>(null);
  const [inviteLink, setInviteLink] = useState<string | null>(null);

  // Profile tab — password change
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [pwSaving, setPwSaving] = useState(false);
  const [pwMessage, setPwMessage] = useState<string | null>(null);

  // Audit tab state
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);

  const isAdmin = me?.role === "admin";

  /** Readable name for a known audit action code; null means show the raw code. */
  const auditActions: Record<string, string> = t.settings.audit.actions;
  function auditActionLabel(action: string): string | null {
    return Object.prototype.hasOwnProperty.call(auditActions, action) ? auditActions[action] : null;
  }

  const loadMe = useCallback(async () => {
    try {
      const meData = await getMe();
      setMe(meData);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err instanceof ApiError ? err.message : t.settings.errors.loadAccount);
    } finally {
      setLoading(false);
    }
  }, [router, t]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    loadMe();
  }, [loadMe, router]);

  // Links from the getting-started checklist open a tab directly (?tab=team).
  useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get("tab");
    if (wanted === "notifications" || wanted === "team" || wanted === "audit" || wanted === "profile") setTab(wanted);
  }, []);

  useEffect(() => {
    if (!me || me.role !== "admin") return;

    if (tab === "notifications" && !notifSettings) {
      getNotificationSettings()
        .then((s) => {
          setNotifSettings(s);
          setNotifEmail(s.notification_email || "");
          if (s.notification_locale) setNotifLocale(s.notification_locale);
        })
        .catch((err) => {
          setError(err instanceof ApiError ? err.message : t.settings.errors.loadNotifications);
        });
    }
    if (tab === "team" && users.length === 0) {
      getUsers()
        .then(setUsers)
        .catch((err) => {
          setError(err instanceof ApiError ? err.message : t.settings.errors.loadTeam);
        });
    }
    if (tab === "audit" && auditLogs.length === 0) {
      getAuditLogs({ limit: 100 })
        .then(setAuditLogs)
        .catch((err) => {
          setError(err instanceof ApiError ? err.message : t.settings.errors.loadAudit);
        });
    }
  }, [tab, me, notifSettings, users.length, auditLogs.length, t]);

  async function handleSaveNotifications() {
    setNotifSaving(true);
    setNotifMessage(null);
    try {
      const updated = await updateNotificationSettings(notifEmail.trim() || null, notifLocale);
      setNotifSettings(updated);
      // A new address is only pending until its owner confirms it.
      setNotifMessage(updated.pending_notification_email
        ? t.settings.notifications.confirmationSent(updated.pending_notification_email)
        : t.settings.notifications.saved);
    } catch (err) {
      setNotifMessage(err instanceof ApiError ? err.message : t.settings.errors.saveSettings);
    } finally {
      setNotifSaving(false);
    }
  }

  async function handleTestNotification() {
    setNotifTesting(true);
    setNotifMessage(null);
    try {
      const result = await sendTestNotification();
      // "skipped" = the server has no SMTP; say so rather than claim success.
      setNotifMessage(result.status.startsWith("skipped") && result.message ? result.message : t.settings.notifications.testSent);
    } catch (err) {
      setNotifMessage(err instanceof ApiError ? err.message : t.settings.errors.sendTest);
    } finally {
      setNotifTesting(false);
    }
  }

  async function handleRoleChange(userId: string, role: TeamUser["role"]) {
    setTeamBusyId(userId);
    setError(null);
    try {
      const updated = await updateUserRole(userId, role);
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.settings.errors.updateRole);
    } finally {
      setTeamBusyId(null);
    }
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    setInviting(true);
    setInviteNotice(null);
    setInviteLink(null);
    setError(null);
    try {
      const created = await inviteUser(inviteEmail.trim().toLowerCase(), inviteRole);
      setUsers((prev) => [...prev, created]);
      setInviteEmail("");
      setInviteNotice(
        created.email_sent
          ? t.settings.team.inviteSent(created.email)
          : t.settings.team.inviteCreated(created.email)
      );
      if (created.invite_url) setInviteLink(created.invite_url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.settings.errors.invite);
    } finally {
      setInviting(false);
    }
  }

  async function handleResend(user: TeamUser) {
    setTeamBusyId(user.id);
    setInviteNotice(null);
    setInviteLink(null);
    setError(null);
    try {
      const result = await resendInvite(user.id);
      setInviteNotice(
        result.email_sent
          ? t.settings.team.resentEmail(user.email)
          : t.settings.team.resentLink(user.email)
      );
      if (result.invite_url) setInviteLink(result.invite_url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.settings.errors.resend);
    } finally {
      setTeamBusyId(null);
    }
  }

  async function handleDeactivate(user: TeamUser) {
    const question =
      user.status === "invited"
        ? t.settings.team.confirmRevoke(user.email)
        : t.settings.team.confirmDeactivate(user.email);
    if (!window.confirm(question)) {
      return;
    }
    setTeamBusyId(user.id);
    setError(null);
    try {
      const updated = await deactivateUser(user.id);
      setUsers((prev) => prev.map((u) => (u.id === user.id ? updated : u)));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.settings.errors.deactivate);
    } finally {
      setTeamBusyId(null);
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setPwSaving(true);
    setPwMessage(null);
    try {
      await changePassword(currentPassword, newPassword);
      // The server bumps token_version, so every session — including this
      // one — is now signed out by design.
      setPwMessage(t.settings.profile.passwordUpdated);
      setTimeout(() => router.push("/login"), 1500);
    } catch (err) {
      setPwMessage(err instanceof ApiError ? err.message : t.settings.errors.changePassword);
      setPwSaving(false);
    }
  }

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-3xl mx-auto">
          <div className="mb-6">
            <h1 className="legion-title text-ink flex items-center gap-2">
              <SettingsIcon size={20} color={palette.brandBright} />
              {t.settings.title}
            </h1>
            <p className="text-ink-faint text-[11px] tracking-[0.1em] uppercase mt-1.5">
              {t.settings.subtitle}
            </p>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <Loader2 size={20} className="animate-spin" />
            </div>
          ) : (
            <>
              {me && (
                <AccessBanner
                  state={me.access_state}
                  trialEndsAt={me.trial_ends_at}
                  isAdmin={isAdmin}
                />
              )}

              {error && (
                <div className="mb-4 text-critical text-xs bg-critical/10 rounded-lg px-3 py-2.5">
                  {error}
                </div>
              )}

              {/* Tabs */}
              <div className="flex flex-wrap gap-1 mb-5 border-b border-line">
                {TABS.map(({ id, Icon }) => (
                  <button
                    key={id}
                    onClick={() => setTab(id)}
                    className={`flex items-center gap-1.5 text-xs font-medium px-3 py-2.5 -mb-px border-b-2 transition-colors ${
                      tab === id
                        ? "border-brand-hover text-ink"
                        : "border-transparent text-ink-faint hover:text-ink-muted"
                    }`}
                  >
                    <Icon size={13} />
                    {t.settings.tabs[id]}
                  </button>
                ))}
              </div>

              {/* Profile tab */}
              {tab === "profile" && me && (
                <div className="flex flex-col gap-4">
                  <AiSettingsSection isAdmin={isAdmin} />
                  <RegionalSettingsSection isAdmin={isAdmin} />
                  <div className="rounded-xl border border-line bg-surface p-4 flex flex-col gap-3">
                    <div className="flex items-center justify-between py-2 border-b border-line">
                      <span className="text-ink-faint text-xs uppercase tracking-wide">{t.common.email}</span>
                      <span className="text-ink text-sm">{me.email}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-line">
                      <span className="text-ink-faint text-xs uppercase tracking-wide">{t.settings.profile.workspace}</span>
                      <span className="text-ink text-sm">{me.tenant_name || "—"}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-line">
                      <span className="text-ink-faint text-xs uppercase tracking-wide">{t.settings.profile.role}</span>
                      <span
                        className="text-xs font-medium px-2 py-0.5 rounded capitalize"
                        style={{
                          color: ROLE_COLOR[me.role],
                          backgroundColor: `${ROLE_COLOR[me.role]}1A`,
                        }}
                      >
                        {t.common.role[me.role]}
                      </span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                      <span className="text-ink-faint text-xs uppercase tracking-wide">{t.settings.profile.tenantId}</span>
                      <span className="text-ink-muted text-xs font-mono">{me.tenant_id}</span>
                    </div>
                  </div>

                  <MfaSection />

                  <form
                    onSubmit={handleChangePassword}
                    className="rounded-xl border border-line bg-surface p-4 flex flex-col gap-3"
                  >
                    <div className="flex items-center gap-2">
                      <KeyRound size={14} color={palette.inkFaint} />
                      <h2 className="text-ink text-sm font-medium">{t.settings.profile.changePassword}</h2>
                    </div>
                    <p className="text-ink-faint text-[11px] -mt-1">
                      {t.settings.profile.changePasswordHint}
                    </p>
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder={t.settings.profile.currentPassword}
                      required
                      autoComplete="current-password"
                      className="w-full bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
                    />
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder={t.settings.profile.newPassword}
                      required
                      minLength={8}
                      autoComplete="new-password"
                      className="w-full bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
                    />
                    {pwMessage && <p className="text-ink-muted text-xs">{pwMessage}</p>}
                    <button
                      type="submit"
                      disabled={pwSaving}
                      className="self-start flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg text-white transition-colors disabled:opacity-60"
                      style={{ backgroundColor: palette.brand }}
                    >
                      {pwSaving ? (
                        <Loader2 size={13} className="animate-spin" />
                      ) : (
                        <KeyRound size={13} />
                      )}
                      {t.settings.profile.updatePassword}
                    </button>
                  </form>
                </div>
              )}

              {/* Notifications tab */}
              {tab === "notifications" && (
                <div className="rounded-xl border border-line bg-surface p-4">
                  {!isAdmin ? (
                    <AdminOnlyNotice />
                  ) : (
                    <div className="flex flex-col gap-4">
                      <div>
                        <label className="text-ink-faint text-xs uppercase tracking-wide">
                          {t.settings.notifications.emailLabel}
                        </label>
                        <p className="text-ink-faint text-[11px] mt-1 mb-2">
                          {t.settings.notifications.emailHint}
                        </p>
                        <input
                          type="email"
                          value={notifEmail}
                          onChange={(e) => setNotifEmail(e.target.value)}
                          placeholder={t.settings.notifications.emailPlaceholder}
                          className="w-full bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
                        />
                      </div>

                      <div>
                        <label htmlFor="notif-locale" className="text-ink-faint text-xs uppercase tracking-wide">
                          {t.settings.notifications.languageLabel}
                        </label>
                        <p className="text-ink-faint text-[11px] mt-1 mb-2">
                          {t.settings.notifications.languageHint}
                        </p>
                        <select
                          id="notif-locale"
                          value={notifLocale}
                          onChange={(e) => setNotifLocale(e.target.value as Locale)}
                          className="bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink outline-none focus:border-brand-hover"
                        >
                          {LOCALES.map(({ code, label }) => (
                            <option key={code} value={code}>{label}</option>
                          ))}
                        </select>
                      </div>

                      {notifSettings?.pending_notification_email && !notifMessage && (
                        <p className="text-ink-muted text-xs">{t.settings.notifications.pending(notifSettings.pending_notification_email)}</p>
                      )}
                      {notifMessage && (
                        <p className="text-ink-muted text-xs">{notifMessage}</p>
                      )}

                      <div className="flex gap-2">
                        <button
                          onClick={handleSaveNotifications}
                          disabled={notifSaving}
                          className="flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg text-white transition-colors disabled:opacity-60"
                          style={{ backgroundColor: palette.brand }}
                        >
                          {notifSaving ? (
                            <Loader2 size={13} className="animate-spin" />
                          ) : (
                            <Save size={13} />
                          )}
                          {t.common.save}
                        </button>
                        <button
                          onClick={handleTestNotification}
                          disabled={notifTesting}
                          className="flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg bg-panel border border-line text-ink-muted hover:text-ink transition-colors disabled:opacity-60"
                        >
                          {notifTesting ? (
                            <Loader2 size={13} className="animate-spin" />
                          ) : (
                            <Send size={13} />
                          )}
                          {t.settings.notifications.sendTest}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Team tab */}
              {tab === "team" && (
                <div className="flex flex-col gap-4">
                  {!isAdmin ? (
                    <div className="rounded-xl border border-line bg-surface p-4">
                      <AdminOnlyNotice />
                    </div>
                  ) : (
                    <>
                      <form
                        onSubmit={handleInvite}
                        className="rounded-xl border border-line bg-surface p-4 flex flex-col gap-3"
                      >
                        <div className="flex items-center gap-2">
                          <UserPlus size={14} color={palette.inkFaint} />
                          <h2 className="text-ink text-sm font-medium">
                            {t.settings.team.inviteHeading}
                          </h2>
                        </div>
                        <p className="text-ink-faint text-[11px] -mt-1">
                          {t.settings.team.inviteHint}
                        </p>
                        <div className="flex flex-col sm:flex-row gap-2">
                          <input
                            type="email"
                            value={inviteEmail}
                            onChange={(e) => setInviteEmail(e.target.value)}
                            placeholder={t.settings.team.emailPlaceholder}
                            required
                            className="flex-1 bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
                          />
                          <select
                            value={inviteRole}
                            onChange={(e) =>
                              setInviteRole(e.target.value as TeamUser["role"])
                            }
                            className="bg-panel border border-line rounded-lg px-2.5 py-2 text-sm text-ink outline-none focus:border-brand-hover capitalize"
                          >
                            <option value="analyst">{t.common.role.analyst}</option>
                            <option value="viewer">{t.common.role.viewer}</option>
                            <option value="admin">{t.common.role.admin}</option>
                          </select>
                          <button
                            type="submit"
                            disabled={inviting}
                            className="flex items-center justify-center gap-1.5 text-xs font-medium px-4 py-2 rounded-lg text-white transition-colors disabled:opacity-60"
                            style={{ backgroundColor: palette.brand }}
                          >
                            {inviting ? (
                              <Loader2 size={13} className="animate-spin" />
                            ) : (
                              <Send size={13} />
                            )}
                            {t.settings.team.inviteButton}
                          </button>
                        </div>

                        {inviteNotice && (
                          <p className="text-ink-muted text-xs">{inviteNotice}</p>
                        )}
                        {inviteLink && (
                          <code className="block text-[11px] text-brand-bright bg-panel border border-line rounded-lg px-3 py-2 break-all">
                            {inviteLink}
                          </code>
                        )}
                      </form>

                      <div className="rounded-xl border border-line bg-surface overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-line text-left">
                              <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                                {t.settings.team.colUser}
                              </th>
                              <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                                {t.settings.team.colRole}
                              </th>
                              <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium text-right">
                                {t.settings.team.colActions}
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {users.map((u) => {
                              const busy = teamBusyId === u.id;
                              const disabled = u.status === "disabled";
                              return (
                                <tr
                                  key={u.id}
                                  className="border-b border-line last:border-b-0"
                                >
                                  <td className="px-4 py-3">
                                    <span
                                      className={
                                        disabled ? "text-ink-faint line-through" : "text-ink"
                                      }
                                    >
                                      {u.email}
                                    </span>
                                    {u.id === me?.id && (
                                      <span className="ml-2 text-[10px] text-ink-faint">{t.settings.team.you}</span>
                                    )}
                                    {u.status !== "active" && (
                                      <span
                                        className="ml-2 text-[10px] px-1.5 py-0.5 rounded capitalize"
                                        style={{
                                          color: disabled ? palette.critical : palette.warning,
                                          backgroundColor: disabled
                                            ? "#EF444419"
                                            : "#F59E0B19",
                                        }}
                                      >
                                        {t.common.userStatus[u.status]}
                                      </span>
                                    )}
                                  </td>
                                  <td className="px-4 py-3">
                                    <select
                                      value={u.role}
                                      disabled={busy || disabled}
                                      onChange={(e) =>
                                        handleRoleChange(
                                          u.id,
                                          e.target.value as TeamUser["role"]
                                        )
                                      }
                                      className="bg-panel border border-line rounded-lg px-2.5 py-1.5 text-xs text-ink outline-none focus:border-brand-hover capitalize disabled:opacity-40"
                                    >
                                      <option value="admin">{t.common.role.admin}</option>
                                      <option value="analyst">{t.common.role.analyst}</option>
                                      <option value="viewer">{t.common.role.viewer}</option>
                                    </select>
                                  </td>
                                  <td className="px-4 py-3">
                                    <div className="flex items-center justify-end gap-1.5">
                                      {u.status === "invited" && (
                                        <button
                                          onClick={() => handleResend(u)}
                                          disabled={busy}
                                          title={t.settings.team.resendTitle}
                                          className="flex items-center gap-1 text-[11px] px-2 py-1.5 rounded-lg bg-panel border border-line text-ink-muted hover:text-ink transition-colors disabled:opacity-50"
                                        >
                                          <MailWarning size={12} />
                                          {t.settings.team.resend}
                                        </button>
                                      )}
                                      {!disabled && u.id !== me?.id && (
                                        <button
                                          onClick={() => handleDeactivate(u)}
                                          disabled={busy}
                                          title={
                                            u.status === "invited"
                                              ? t.settings.team.revokeTitle
                                              : t.settings.team.deactivateTitle
                                          }
                                          className="flex items-center gap-1 text-[11px] px-2 py-1.5 rounded-lg bg-panel border border-line text-ink-muted hover:text-critical hover:border-critical/40 transition-colors disabled:opacity-50"
                                        >
                                          {busy ? (
                                            <Loader2 size={12} className="animate-spin" />
                                          ) : (
                                            <Ban size={12} />
                                          )}
                                          {u.status === "invited" ? t.settings.team.revoke : t.settings.team.deactivate}
                                        </button>
                                      )}
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                        {users.length === 0 && (
                          <div className="text-center py-12 text-ink-faint text-sm">
                            {t.settings.team.empty}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Audit log tab */}
              {tab === "audit" && (
                <div className="rounded-xl border border-line bg-surface overflow-hidden">
                  {!isAdmin ? (
                    <div className="p-4">
                      <AdminOnlyNotice />
                    </div>
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-line text-left">
                          <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                            {t.settings.audit.colAction}
                          </th>
                          <th className="hidden sm:table-cell px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                            {t.settings.audit.colBy}
                          </th>
                          <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium">
                            {t.settings.audit.colWhen}
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {auditLogs.map((log) => {
                          const actionLabel = auditActionLabel(log.action);
                          return (
                            <tr
                              key={log.id}
                              className="border-b border-line last:border-b-0"
                            >
                              <td className="px-4 py-3">
                                {actionLabel ? (
                                  <p className="text-ink text-xs" title={log.action}>
                                    {actionLabel}
                                  </p>
                                ) : (
                                  <p className="text-ink text-xs font-mono">{log.action}</p>
                                )}
                                {log.detail && (
                                  <p className="text-ink-faint text-[11px] mt-0.5">
                                    {log.detail}
                                  </p>
                                )}
                              </td>
                              <td className="hidden sm:table-cell px-4 py-3 text-ink-muted text-xs">
                                {log.user_email || "—"}
                              </td>
                              <td className="px-4 py-3 text-ink-faint text-xs">
                                {formatDateTime(log.created_at, locale)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                  {isAdmin && auditLogs.length === 0 && (
                    <div className="text-center py-12 text-ink-faint text-sm">
                      {t.settings.audit.empty}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
