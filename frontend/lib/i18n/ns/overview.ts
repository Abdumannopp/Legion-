import { defineMessages } from "../core";

/**
 * The dashboard's first answer: am I protected, what threats are open, what
 * Legion blocked, and what is left to set up. Every number shown with these
 * words comes from GET /overview.
 */
export const overview = defineMessages({
  en: {
    status: {
      not_connected: { title: "Not connected yet", body: "Connect a security sensor so Legion can watch your computers. It takes about five minutes." },
      waiting_for_data: { title: "Connected — waiting for the first event", body: "Your sensor is set up. Legion is waiting for it to report something." },
      attention: { title: "Needs your attention", body: "Legion is watching. Some things below need a decision from you." },
      protected: { title: "Protected", body: "Your sensors are reporting and nothing urgent is open." },
    },
    reasons: {
      no_sources: "No sensor is connected, so Legion can't see threats on your computers yet.",
      no_events_yet: "No event has arrived yet. Sensors only forward serious events, so this can take a while.",
      open_critical: "There are open critical threats.",
      open_high: "There are open high-severity threats.",
      source_silent: "A connected sensor has gone quiet. It may be down or disconnected.",
      approvals_pending: "An AI agent is waiting for your approval.",
      agent_contained: "Legion paused or stopped an AI agent this week.",
    } as Record<string, string>,
    connectCta: "Connect a sensor",
    protectedTitle: "What's protected",
    sources: (n: number) => (n === 1 ? "1 connected source" : `${n} connected sources`),
    devices: (n: number, online: number) => `${n} computers and devices · ${online} online`,
    agentsLine: (n: number, active: number) => (n === 1 ? `1 AI agent · ${active} working` : `${n} AI agents · ${active} working`),
    noSources: "Nothing connected yet.",
    health: {
      receiving: "Receiving events",
      waiting: "Waiting for first event",
      silent: "No events recently",
      error: "Connection problem",
      paused: "Paused",
    } as Record<string, string>,
    lastEvent: (s: string) => `last event ${s}`,
    threatsTitle: "Open threats",
    noThreats: "No open threats.",
    newToday: (n: number) => `${n} new in the last 24 hours`,
    blockedTitle: "What Legion blocked",
    blockedWindow: (days: number) => `AI agent actions, last ${days} days`,
    refused: "Blocked",
    contained: "Agent paused or stopped",
    waiting: "Waiting for you",
    noBlocks: "Nothing blocked. Every AI agent action this week was within its permissions.",
    noAgents: "No AI agents yet. When you add one, Legion checks every action it takes.",
    review: "Review",
    unknownAgent: "An AI agent",
    checklist: {
      title: "Getting started",
      progress: (done: number, total: number) => `${done} of ${total} done`,
      optional: "Optional",
      steps: {
        connect: { title: "Connect a security sensor", hint: "Link Wazuh (or another sensor) so Legion sees what happens on your computers.", action: "Connect" },
        first_event: { title: "Receive your first event", hint: "Legion confirms the connection when the first real event arrives.", action: "Check connection" },
        notifications: { title: "Choose where alerts are emailed", hint: "So you hear about critical threats even when Legion isn't open.", action: "Set up" },
        team: { title: "Invite your team", hint: "Share the work — each person gets their own sign-in and role.", action: "Invite" },
        agent: { title: "Protect an AI agent", hint: "Give an AI agent its own key and limits. Legion checks everything it does.", action: "Add agent" },
      },
    },
    sourceLabel: {
      wazuh: "Wazuh",
      "legion-test": "Test alert",
      "legion-monitor": "Legion monitoring",
      "legion-agent-security": "AI agent protection",
      "legion-correlation": "Attack correlation",
      mock: "Sample data",
    } as Record<string, string>,
    testBadge: "Test",
    whatToDo: "What to do",
  },
});
