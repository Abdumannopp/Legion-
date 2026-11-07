import { defineMessages } from "../core";

/** Protection modes card (components/ProtectionSection.tsx): how much Legion may do on its own. */
export const protection = defineMessages({
  en: {
    title: "Protection mode",
    intro: "Legion watches around the clock. Here you decide how much it may do on its own when it finds an attack. You stay in control: you can switch it off or press the emergency stop at any time.",
    modes: {
      manual: { name: "Manual", help: "Legion detects, explains and proposes. Nothing is done until a person does it. (Default.)" },
      hybrid: { name: "Hybrid", help: "Legion does on its own only what you tick below. Anything else waits for your approval." },
      automatic: { name: "Automatic", help: "Legion does on its own everything it is able to do and that is not critical. Critical actions and anything proposed by an AI model still wait for a person." },
    },
    now: {
      manual: "Legion is in manual mode: it does nothing on its own.",
      hybrid: "Legion acts on its own for the actions you ticked.",
      automatic: "Legion acts on its own for everything it can do that is not critical.",
      needsNotice: "The notice changed since you accepted it. Legion is in manual mode until an administrator accepts it again.",
    },
    actions: {
      title: "Allowed without asking (hybrid)",
      "ip.block": "Block an attacking address for a limited time",
      "notify.admins": "E-mail the administrators",
      reversible: "can be undone",
      other: "Everything else Legion can propose (disabling accounts, isolating hosts, moving money) stays simulation-only: it cannot be done by Legion, and always needs a person.",
    },
    notice: {
      title: "Before Legion may act on its own",
      accept: "I have read this notice and I allow Legion to act on its own in my workspace, as chosen above.",
      required: "Accept the notice to turn this on.",
    },
    save: "Save",
    saved: "Saved",
    adminOnly: "Only administrators can change this.",
    planLocked: "Automatic protection is not part of your plan. Upgrade to let Legion act on its own.",
    limit: (n: number) => `At most ${n} actions an hour are done on Legion's own; after that each one waits for a person.`,
    stop: {
      title: "Emergency stop",
      help: "Immediately refuses new actions and holds queued ones. Nothing already done is undone.",
      press: "Stop everything",
      lift: "Lift the stop",
      active: "Emergency stop is ON: Legion is not acting.",
    },
    approvals: {
      title: "Waiting for your decision",
      empty: "Nothing is waiting for you.",
      approve: "Approve",
      reject: "Reject",
      code: "Authenticator code",
      requestedBy: (who: string) => `Proposed by ${who}`,
      expires: "Expires",
      failed: "Could not record your decision.",
    },
    report: {
      title: "What Legion did (last 7 days)",
      automatic: "On its own",
      approved: "After your approval",
      byPerson: "By a person",
      waiting: "Waiting for a decision",
      failed: "Could not be done",
      empty: "Nothing yet.",
      recent: "Recent",
      status: { executed: "Done", failed: "Failed", awaiting_approval: "Waiting", queued: "Queued", running: "Running", denied: "Refused", rejected: "Rejected", expired: "Expired", cancelled: "Cancelled" } as Record<string, string>,
      by: { person: "a person", system: "Legion" } as Record<string, string>,
    },
  },
});
