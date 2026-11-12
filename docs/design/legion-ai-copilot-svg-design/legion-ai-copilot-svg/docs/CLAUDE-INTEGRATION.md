# LEGION AI Copilot — SVG handoff

## Included
- `ai-copilot/legion-ai-copilot.svg` — editable vector mockup (1600 × 1000).
- This guide — implementation notes for Claude / the existing frontend.

## Design intent
Premium dark SOC interface with restrained violet accents, glass-like panels, high-contrast typography, a central AI conversation, and a right-side investigation context rail.

## Integration instructions
1. Inspect the existing application structure and identify the current AI Copilot route/page before changing files.
2. Use the SVG as a visual reference or embed it as a static preview. Do not replace the working application with a static screenshot.
3. Rebuild the interface with the project's existing React/Next.js, TypeScript, and Tailwind conventions. Reuse existing layout, navigation, auth, theme, and shared components.
4. Preserve current API clients, routing, role checks, tenant boundaries, loading/error states, and responsive behavior.
5. Connect the chat composer to the real approved AI backend. Show streaming, cancellation, retry, empty, loading, and error states where supported.
6. Populate related alerts, host context, MITRE mappings, and risk values from real authorized telemetry. Do not present the illustrative values in this SVG as live data.
7. Treat AI output as advisory. Require explicit analyst confirmation and backend authorization for actions such as host isolation, alert closure, or blocking indicators. Never execute a response action merely because the model suggested it.
8. Add keyboard navigation, visible focus states, semantic headings, accessible labels, and responsive layouts. On narrow screens, stack the context rail below the conversation or expose it as a collapsible panel.

## Data and safety notes
- The SVG's example host `WS-042`, alert descriptions, risk score, timestamps, and MITRE techniques are illustrative UI content only.
- Do not hardcode secrets, tokens, credentials, or API endpoints in client code.
- Enforce permissions and tenant isolation on the server, not only in the UI.
- Keep severity/status colors semantically distinct from the brand violet accent.

## Suggested component breakdown
- `AICopilotPage`
- `CopilotHeader`
- `SuggestedPrompts`
- `ConversationThread`
- `AssistantMessage`
- `InvestigationContext`
- `RelatedAlerts`
- `HostRiskSnapshot`
- `RecommendedActions`
- `CopilotComposer`

## Acceptance checklist
- [ ] Existing application routes and authentication still work.
- [ ] Chat sends to the real backend and handles streaming/errors.
- [ ] Context rail is backed by authorized live data.
- [ ] Suggested prompts populate the composer or start a supported query.
- [ ] No destructive/security action runs without explicit user confirmation.
- [ ] Layout works at desktop, tablet, and mobile widths.
- [ ] Keyboard and screen-reader interactions are usable.
- [ ] No illustrative SVG data is shown as live telemetry.
