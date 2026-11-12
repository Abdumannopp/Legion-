import { defineMessages } from "../core";

/**
 * The public website: product page (Landing), site header and footer, and
 * the pricing card. The English copy is what Paddle's reviewers read — keep
 * it faithful to the product; 
 */


export const site = defineMessages({
  en: {
    header: {
      homeAria: "Legion home",
      features: "Features",
      pricing: "Pricing",
      startTrial: (days: number) => `Start ${days}-day trial`,
      tryFree: "Try free",
    },
    footer: {
      merchantNotice: (seller: string) =>
        `Legion is provided by ${seller}. Orders are processed by our online reseller Paddle.com, which is the Merchant of Record for all orders and handles billing, invoices and payment-related customer service.`,
      pricing: "Pricing",
      terms: "Terms",
      freeTrial: "Free trial",
      privacy: "Privacy",
      contact: "Contact",
      refunds: "Refunds",
    },
    landing: {
      heroTitle: "Stop chasing alerts.",
      heroTitleAccent: "Start stopping threats.",
      heroText:
        "Legion watches your computers and your AI agents, explains every threat in plain language, and stops risky AI actions before they happen — so a small team can respond like a big one.",
      ctaTrial: (days: number) => `Start ${days}-day free trial`,
      ctaPricing: "See pricing",
      noCard: "No credit card required.",
      highlights: ["Works with Wazuh", "Explains every alert in plain language", "You decide what runs automatically"],
      featuresEyebrow: "What you get",
      featuresTitle: "From alert to decision",
      features: {
        realtime: {
          title: "Connected in minutes",
          text: "Link the security sensor you already run — Wazuh today, more on the way — and alerts appear the moment they happen. No polling, no spreadsheets.",
        },
        explained: {
          title: "Explained, not just listed",
          text: "Every alert gets a plain-language explanation and a next step: what happened, why it matters, what to check first.",
        },
        triage: {
          title: "Triage to resolution",
          text: "Open, investigate, resolve. Severity, MITRE technique, source and target on every incident, with a full history of who did what.",
        },
        assets: {
          title: "Asset inventory",
          text: "The machines behind your alerts are catalogued automatically from your sensors, with risk and last-seen status.",
        },
        agents: {
          title: "AI agents with guardrails",
          text: "Give automation its own identity and only the permissions it needs. Every action passes a policy firewall and is audited.",
        },
        secure: {
          title: "Built like a security product",
          text: "Two-factor sign-in, role-based access, an append-only audit log, and each customer's data isolated in its own workspace.",
        },
      },
      stepsEyebrow: "How it works",
      steps: {
        create: {
          title: "Create a workspace",
          text: (days: number) => `Sign up with your work email. ${days} days free, no card.`,
        },
        connect: {
          title: "Connect your sensors",
          text: "Create a key, paste one block into your sensor's settings, and Legion tells you when the first event arrives.",
        },
        act: {
          title: "Act on what matters",
          text: "Critical alerts rise to the top with an explanation and a next step.",
        },
      },
      pricingEyebrow: "Pricing",
      pricingTitle: "Plans for every size of team",
      trust: {
        access: "Two-factor sign-in and role-based access",
        audited: "Every administrative action audited",
        neverSold: "Your alert data is never sold",
      },
    },
  },
});
