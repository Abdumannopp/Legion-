import { LegalDoc } from "./privacy";
import type { Locale } from "@/lib/i18n/core";
import { DATA_LOCATION } from "@/lib/site";

/**
 * Legal pages for the HOSTED service (NEXT_PUBLIC_DEPLOYMENT_MODE=saas), where
 * {operator} is the seller — the company or sole proprietor who runs Legion
 * for paying customers — and Paddle.com is the Merchant of Record.
 *
 * These are a starting point written to match what the software actually
 * does. They are not legal advice: have them reviewed before relying on them.
 * English is the binding text (Paddle reviews it in English). The Russian and
 * Uzbek versions are convenience translations, and each says in its intro
 * that the English version prevails if they differ — keep them in step with
 * the English whenever it changes.
 *
 * {operator}, {supportEmail} and {dataLocation} are filled in at render time.
 */
const EFFECTIVE = "September 28, 2026";
const EFFECTIVE_RU = "28 сентября 2026 г.";
const EFFECTIVE_UZ = "2026-yil 28-sentabr";

export const saasTerms: Record<Locale, LegalDoc> = {
  en: {
    title: "Terms of Service",
    effectiveDate: EFFECTIVE,
    intro:
      "These terms are an agreement between you (the organisation that signs up, and the person accepting on its behalf) and {operator} (\"we\", \"us\"), who provides the Legion security operations service at this website. By creating an account or using the service you accept them.",
    sections: [
      {
        heading: "1. The Service",
        body: [
          "Legion is a hosted security operations console. It receives security alerts from systems you connect (such as a Wazuh manager), stores them in your workspace, explains them, and helps your team track them to resolution.",
          "The service is intended for businesses and professionals, not consumers. You must be at least 18 and able to bind the organisation you sign up for.",
        ],
      },
      {
        heading: "2. Accounts",
        body: [
          "You are responsible for everything done under your workspace's accounts. Keep passwords and two-factor devices private, give each person their own account, and remove people who leave.",
          "Tell us promptly at {supportEmail} if you believe an account has been compromised.",
        ],
      },
      {
        heading: "3. Acceptable Use",
        body: [
          "Connect only systems you own or are authorised to monitor, and send only data you are allowed to process.",
          "Do not use the service to break the law, to attack or probe systems you are not authorised to test, to try to access another customer's workspace, to overload the service, or to resell it without our written agreement.",
          "We may suspend accounts that put the service or other customers at risk. Where possible we will tell you first and give you a chance to fix the problem.",
        ],
      },
      {
        heading: "4. Free Trial",
        body: [
          "New workspaces get a free trial (the length is shown when you sign up). No payment details are needed for the trial. When it ends, the workspace is locked until you subscribe; your data is kept so you can continue where you left off.",
        ],
      },
      {
        heading: "5. Subscriptions, Payment and Our Reseller",
        body: [
          "Our order process is conducted by our online reseller Paddle.com. Paddle.com is the Merchant of Record for all our orders. Paddle provides all customer service inquiries and handles returns.",
          "Subscriptions renew automatically at the end of each billing period at the then-current price until cancelled. Prices, currency and applicable taxes are shown at checkout. We will give at least 30 days' notice of a price increase for existing subscriptions.",
          "You can cancel at any time from Billing → Manage subscription. Cancellation takes effect at the end of the current paid period; you keep access until then.",
          "If a payment fails, the workspace becomes read-only until it is settled, and is locked if the subscription ends. Refunds are described in our Refund Policy.",
        ],
      },
      {
        heading: "6. Your Data",
        body: [
          "Everything you and your systems put into your workspace remains yours. You give us permission to store and process it only to provide, secure and support the service for you.",
          "We do not sell your data or use it to advertise to anyone. How we handle it is described in our Privacy Policy.",
          "Each customer's data is kept in its own workspace, and our staff access it only when needed to operate the service, to resolve a support request you make, or when the law requires it.",
        ],
      },
      {
        heading: "7. AI Features",
        body: [
          "Explanations, suggested next steps and other AI-assisted output are aids to your judgement, not verified findings. They can be wrong or incomplete. Check them before acting, particularly before disruptive actions such as isolating a system.",
        ],
      },
      {
        heading: "8. Availability and Changes",
        body: [
          "We work to keep the service available and secure, but we do not guarantee uninterrupted or error-free operation, and the service does not replace your own security controls, backups or incident response obligations.",
          "We may improve or change features. If we make a change that materially reduces what you pay for, we will tell you in advance, and you may cancel.",
        ],
      },
      {
        heading: "9. Ending the Agreement",
        body: [
          "You may stop using the service and cancel at any time. We may end the agreement on 30 days' notice, or immediately for serious or repeated breach of these terms.",
          "After your subscription ends your workspace is locked, not erased. Ask us at {supportEmail} to delete it and we will do so within 30 days, except where the law requires us to keep something.",
        ],
      },
      {
        heading: "10. Liability",
        body: [
          "The service is provided \"as is\" to the extent the law allows. We are not liable for indirect or consequential losses, lost profits or lost data that proper backups would have preserved.",
          "Our total liability for any claim is limited to the amount you paid for the service in the 12 months before the claim arose. Nothing in these terms limits liability that cannot be limited by law.",
        ],
      },
      {
        heading: "11. Changes to These Terms, and Law",
        body: [
          "We may update these terms. For material changes we will notify workspace administrators by email at least 30 days before they take effect.",
          "These terms are governed by the laws of the Republic of Uzbekistan, without prejudice to mandatory rights you have under the law of your own country.",
        ],
      },
    ],
  },
};

export const saasPrivacy: Record<Locale, LegalDoc> = {
  en: {
    title: "Privacy Policy",
    effectiveDate: EFFECTIVE,
    intro:
      "This policy explains what personal data {operator} (\"we\") processes when you use the Legion service, why, who helps us, and the choices you have. For the security data your systems send into your workspace, your organisation decides what is collected; we process it on your organisation's behalf.",
    sections: [
      {
        heading: "1. What We Store",
        body: [
          "Account data: your email address, the name of your organisation, your role, and your password — stored only as a bcrypt hash, never in readable form. If you turn on two-factor sign-in, the shared secret and hashed recovery codes.",
          "Session and security records: for each sign-in, the IP address and browser user-agent it came from; and an audit log of administrative actions (who, what, when, from which IP address).",
          "Workspace data: the alerts, IP addresses, hostnames and asset details your connected systems send. This can include personal data about people on your network; your organisation controls it.",
          "Billing status: whether your subscription is active, and the customer and subscription identifiers Paddle gives us. We never see or store your card details — Paddle does.",
          "Support messages you send us.",
        ],
      },
      {
        heading: "2. Why",
        body: [
          "To provide the service you signed up for (contract), to keep it and your account secure and prevent abuse (legitimate interest), to bill you through our reseller (contract), and to meet legal obligations such as tax records (legal obligation).",
          "We do not sell personal data, do not use your workspace data to train AI models, and do not use advertising or analytics trackers on the service.",
        ],
      },
      {
        heading: "3. Who Helps Us",
        body: [
          "Paddle.com — our reseller and Merchant of Record. When you buy, you give your billing details to Paddle, and Paddle's own privacy policy applies to them.",
          "Our hosting provider, which runs the servers your workspace is stored on, located in {dataLocation}.",
          "Our email delivery provider, which sends account emails (confirmation, password reset, invitations) and the alert notifications you enable. It receives the recipient address and the message content.",
          "An AI provider, only when AI analysis is switched on for the service: alert titles, descriptions, hostnames and IP addresses are then sent to it to produce explanations. When it is off, explanations are generated on our own servers and nothing is sent.",
          "Cloudflare, which may sit in front of the service to filter attacks and, on sign-in pages, to check that a visitor is a person. It sees the traffic to and from the service.",
          "Each of these processes data only to provide its part of the service.",
        ],
      },
      {
        heading: "4. Cookies",
        body: [
          "We use only the cookies needed to keep you signed in and to protect your session. The checkout and billing pages load Paddle's payment script, which may set its own cookies needed to process payments.",
        ],
      },
      {
        heading: "5. How Long We Keep It",
        body: [
          "Account and workspace data are kept while your account exists. Resolved alerts are deleted automatically once they are older than your plan's alert history (30, 90, 180 or 365 days); open alerts are kept until they are resolved. After a subscription ends the workspace is locked but kept, so you can return; ask us to delete it and we will do so within 30 days.",
          "We keep encrypted backups for up to 12 months. Data you delete can remain in a backup until that backup expires; it is not used for anything else, and if a backup is ever restored, deletions made since then are applied again.",
          "The workspace audit log records who did what. After 24 months the email address and IP address in an entry are removed, leaving only an anonymous user identifier. Payment-check records are deleted after 24 months.",
          "Billing and tax records are kept by Paddle and by us for as long as the law requires.",
        ],
      },
      {
        heading: "6. Security",
        body: [
          "Connections are encrypted (HTTPS). Passwords and recovery codes are stored only as hashes, two-factor sign-in is available to every user, each customer's data is isolated in its own workspace, and administrative actions are recorded in an audit log.",
          "If a breach affecting your personal data occurs, we will notify affected workspace administrators without undue delay.",
        ],
      },
      {
        heading: "7. Your Rights",
        body: [
          "You can ask to access, correct, export or delete your personal data, or object to how it is used, by writing to {supportEmail}. For data inside a workspace, we will act on the instructions of that workspace's administrators.",
          "You also have the right to complain to your local data-protection authority.",
        ],
      },
      {
        heading: "8. Changes",
        body: [
          "If we change this policy materially, we will tell workspace administrators by email before the change takes effect.",
        ],
      },
    ],
  },
};

export const saasRefunds: Record<Locale, LegalDoc> = {
  en: {
    title: "Refund Policy",
    effectiveDate: EFFECTIVE,
    intro:
      "Legion starts with a free trial so you can decide before paying anything. If you subscribe and it still isn't right for you, this policy explains how to get your money back.",
    sections: [
      {
        heading: "1. 14-Day Refund on Your First Payment",
        body: [
          "If you are not satisfied, request a refund within 14 days of your first subscription payment and you will receive a full refund of that payment. Your workspace is then locked.",
        ],
      },
      {
        heading: "2. Renewals",
        body: [
          "Renewal payments are not refunded, but you can cancel at any time from Billing → Manage subscription so that you are not charged again. You keep access until the end of the period already paid for.",
          "If you were charged in error — for example, a renewal after you had cancelled — tell us and we will put it right.",
        ],
      },
      {
        heading: "3. How to Ask",
        body: [
          "Email {supportEmail} from your account's email address, or use the link in the receipt Paddle sent you. Payments are handled by our reseller Paddle.com, which processes refunds back to the original payment method, usually within 5–10 business days depending on your bank.",
        ],
      },
      {
        heading: "4. Your Statutory Rights",
        body: [
          "Nothing in this policy limits rights you have under the consumer law of your country.",
        ],
      },
    ],
  },
};

/** Fills {dataLocation}; resolveLegalDoc fills {operator} and {supportEmail}.
 *  Takes one language's document, e.g. `withDataLocation(saasPrivacy[locale])`. */
export function withDataLocation(doc: LegalDoc): LegalDoc {
  const fill = (t: string) => t.replace(/\{dataLocation\}/g, DATA_LOCATION);
  return { ...doc, intro: fill(doc.intro), sections: doc.sections.map((s) => ({ heading: fill(s.heading), body: s.body.map(fill) })) };
}
