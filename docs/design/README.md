# Design references

The seven design packs this interface follows (premium dark, Spartan brand). They are **references**, not shipped
screens: every number, host, IP address and name in them is an illustrative placeholder. The product shows only
real data from the API, and an honest empty state where there is none.

| Pack | Where it lives in the product |
|---|---|
| `legion-global-design-system` | `frontend/lib/theme.ts` (palette, one severity scale), `frontend/app/globals.css` (`lg-*` surfaces, glass, buttons, inputs, status chips, tables, motion), `tailwind.config.ts` |
| `legion-premium-svg-pack` | `frontend/public/brand/` (horizontal, stacked, mark, favicon), `components/brand/*`, `app/icon.*` |
| `legion-dashboard-premium-svg` | `components/LegionDashboard.tsx`, `components/DashboardWidgets.tsx` (KPI cards and the severity ring from `GET /overview`) |
| `legion-alerts-incidents-svg` | `app/incidents/page.tsx` (severity cards from `GET /alerts/stats`, chips, keyboard rows), alert rows on the dashboard |
| `legion-ai-copilot-svg-design` | `app/copilot/page.tsx` (prompt cards, conversation, context rail of real open alerts, "a person decides") |
| `legion-login-landing-svg` | `app/login/page.tsx` (glass card, icons, show-password), `components/site/Landing.tsx` |
| `legion-mobile-ux-animations-svg` | `components/Sidebar.tsx` (bottom navigation and "More" sheet on phones), `lg-enter` / `lg-new` motion, reduced-motion respected |

Not taken from the designs on purpose: a "security score" (Legion has no such measure), charts for data the API
does not keep (events per hour, MITRE share), social sign-in buttons (no such providers are configured), app-store
badges and push notifications (there is no mobile app), and a one-tap "isolate host" (Legion never acts from an AI
suggestion). `legion-dashboard-premium.svg` has an unescaped `&` in its description and does not open in strict SVG
viewers; it is kept as received.
