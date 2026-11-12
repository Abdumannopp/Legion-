# LEGION Global Design System — Apple-inspired Premium

This design system is tailored to the supplied Legion frontend (Next.js 16, React 18, Tailwind CSS 3, TypeScript). It extends the existing dark-violet identity rather than replacing the brand.

## Package contents
- `tokens/tokens.ts` — typed source-of-truth design tokens.
- `styles/globals-design-system.css` — surface, glass, button, form, status, table and motion primitives.
- `preview/legion-design-system.svg` — visual reference sheet.
- `CLAUDE-INTEGRATION.md` — implementation brief for Claude.

## Art direction
Apple-inspired premium minimalism: restrained glass surfaces, soft depth, careful typography, generous spacing, quiet gradients and purposeful motion. Keep the Spartan helmet identity. Do not copy Apple logos, proprietary UI assets or exact product screens.

## Integration with current codebase
The supplied project already has:
- `frontend/lib/theme.ts`
- `frontend/tailwind.config.ts`
- `frontend/app/globals.css`
- system font stack and a violet palette
- semantic severity colors

Do not create a parallel competing theme. Merge these tokens into the existing `palette` source of truth and preserve existing token names (`canvas`, `panel`, `surface`, `line`, `ink`, `brand`, `critical`, `warning`, `success`, `info`) so current Tailwind classes keep working. Add new tokens incrementally.

## Claude implementation sequence
1. Read the existing theme, globals.css, tailwind config and all component usages before editing.
2. Merge token values into `frontend/lib/theme.ts`; keep semantic severity colors distinct from brand violet.
3. Merge CSS primitives into `frontend/app/globals.css`; retain Tailwind directives and current rules.
4. Add only Tailwind aliases that improve consistency; do not rename/remove existing classes.
5. Refactor components incrementally: buttons, inputs, cards, badges, tables, dialogs, navigation, charts.
6. Preserve all API calls, auth, routes, permissions, i18n, alert actions and Wazuh integration.
7. Use real data only. Do not ship illustrative sample metrics as live data.
8. Use purple for brand/selection, never to imply severity. Keep critical/high/medium/low/healthy semantics clear.
9. Ensure keyboard focus, contrast, accessible labels, reduced motion and responsive behavior.
10. Run `npm run lint`, `npm test` and `npm run build` from `frontend`; report pre-existing failures separately.

## Usage examples
- Panel: `className="lg-surface p-5"`
- Glass overlay: `className="lg-glass"`
- Primary action: `className="lg-button-primary"`
- Input: `className="lg-input"`
- Severity: `className="lg-status lg-status-critical"`
- Table: `className="lg-table-wrap"` around `lg-table`

## Design principles
- App canvas: `#08060F`
- Raised surfaces: `#151020` / `#1C1429`
- Primary violet: `#8B5CF6`
- Primary text: `#F8F7FC`
- Secondary text: `#A99DBB`
- Rounded geometry: 10–28px
- Animation: 140–360ms, restrained and optional
- Glass blur: use only on overlays/selected surfaces, not every card
- Typography: system-first; never depend on an unavailable proprietary font
