/**
 * What the public pages need to know about how this Legion is offered.
 * All build-time (NEXT_PUBLIC_*): `npm run setup -- --saas` writes them into
 * frontend/.env.local, and the dashboard must be rebuilt after changing them.
 */

/** "saas": the hosted service — landing, pricing, self-sign-up, Paddle.
 *  Anything else: one organisation's own installation. */
export const IS_SAAS = process.env.NEXT_PUBLIC_DEPLOYMENT_MODE === "saas";

/** Who sells the service: the legal name of the company or sole proprietor.
 *  Paddle's review requires it in the Terms. Conspicuous when unset. */
export const SELLER = process.env.NEXT_PUBLIC_OPERATOR_NAME || "[your legal name]";

/** Shown until Paddle's localized price has loaded (or if it cannot load). */
export const PRICE_FALLBACK = process.env.NEXT_PUBLIC_PRICE_LABEL || "";

export const TRIAL_DAYS = Number(process.env.NEXT_PUBLIC_TRIAL_DAYS || 14);

/** Country (or region) where the server that stores customer data runs —
 *  the Privacy Policy names it. Conspicuous when unset. */
export const DATA_LOCATION = process.env.NEXT_PUBLIC_DATA_LOCATION || "[the country of your server]";
