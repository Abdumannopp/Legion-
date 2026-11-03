import { defineMessages } from "../core";

/**
 * Connect: bringing a sensor's events into Legion. Wazuh is one integration
 * among others here — the page is organised around "what do you want Legion
 * to watch", and the Wazuh specifics sit inside its own card.
 */
export const connect = defineMessages({
  en: {
    title: "Connect",
    intro: "Connect the tools that watch your computers and systems. Legion collects their events, explains them in plain language, and tells you what to do.",
    adminOnly: "Only workspace admins can connect integrations. Ask an admin to set this up — you'll see alerts here as soon as it's done.",
    available: "Available",
    soon: "Coming soon",
    connected: "Connected",
    waiting: "Waiting for first event",
    setUp: "Set up",
    close: "Close",
    agentsCard: {
      title: "AI agents",
      body: "Protect your AI agents and the tools they use, including MCP servers and agent-to-agent calls.",
      action: "Go to AI agents",
    },
    wazuh: {
      summary: "Open-source security monitoring for servers and laptops. If you run Wazuh, Legion receives its alerts as they happen.",
      step1: {
        title: "Create a connection key",
        body: "Legion gives your Wazuh server its own key, so only it can send events to this workspace.",
        label: "Name for this connection",
        labelPlaceholder: "e.g. Production Wazuh",
        action: "Create key",
      },
      step2: {
        title: "Add Legion to your Wazuh server",
        files: "Copy Legion's two integration files (custom-legion and custom-legion.py, in the integrations folder of the Legion package) to /var/ossec/integrations/ on the Wazuh server.",
        conf: "Add this block inside <ossec_config> in /var/ossec/etc/ossec.conf, then restart Wazuh.",
        keyOnce: "The key inside this block is shown only once. Copy it now — if it's lost, create a new key.",
        keyHidden: "The key was shown when it was created. If you don't have it, create a new key.",
      },
      step3: {
        title: "Check the connection",
        waiting: "Waiting for the first event from Wazuh…",
        connected: "Connected — Legion received an event from Wazuh.",
        hint: "Wazuh forwards only alerts of level 7 and above, so the first one can take a while. Meanwhile, send a test alert to see how alerts look and check that notifications reach you.",
      },
      technical: "Technical details",
      technicalItems: {
        commands: "Commands on the Wazuh server",
        endpoint: "Legion receives events at",
        level: "Minimum alert level forwarded: 7 (change <level> to forward more or fewer).",
        docs: "Full guide, including key rotation and troubleshooting: WAZUH.md in the Legion package.",
      },
    },
    test: {
      action: "Send a test alert",
      sent: "Test alert sent — it's on your dashboard, marked as a test.",
      hint: "Shows what an alert looks like and checks that notifications reach you. It doesn't prove your sensor is connected.",
    },
    keys: {
      title: "Connection keys",
      none: "No keys yet.",
      lastUsed: (s: string) => `Last event ${s}`,
      neverUsed: "No events yet",
      revoke: "Revoke",
      revokeConfirm: "Revoke this key? The Wazuh server using it will no longer be able to send events.",
      revoked: "Key revoked.",
      status: { active: "Active", rotating: "Being replaced", expired: "Expired", revoked: "Revoked" } as Record<string, string>,
    },
    copy: "Copy",
    copied: "Copied",
  },
});
