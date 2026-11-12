# LEGION Premium Dashboard SVG Pack

This pack contains a scalable SVG dashboard concept for:
**LEGION — CYBERSECURITY INTELLIGENCE**

## Files
- `dashboard/legion-dashboard-premium.svg` — 1600×1000 full dashboard visual concept.

## Claude integration instructions
Use this SVG as a visual reference, not as a static replacement for the application UI.

1. Inspect the existing frontend routes, dashboard components, design tokens, data hooks and Wazuh/API integrations.
2. Rebuild the layout as responsive React components using the existing stack and component conventions.
3. Use the SVG as the visual target for spacing, hierarchy, colors, cards, charts, tables and navigation.
4. Keep all values connected to real application data. The numbers shown in the concept are illustrative placeholders; never ship them as real metrics.
5. Use the existing backend/API data for Security Score, active threats, incidents, endpoints, alert table and agent status. If a metric is unavailable, show an honest empty/unavailable state.
6. Preserve routes, authentication, permissions, alert actions, filters and existing business logic.
7. Make charts accessible and responsive; use the project's existing chart library if present.
8. Keep the Spartan LEGION mark and exact tagline: `CYBERSECURITY INTELLIGENCE`.
9. Verify desktop, tablet and mobile breakpoints, keyboard navigation, loading/error/empty states.
10. Run lint, type-check and production build; report any pre-existing failures separately.

## Visual tokens
- Background: `#090510`
- Panel: `#251638` / `#171024`
- Primary violet: `#A855F7`
- Deep violet: `#6D28D9`
- Highlight: `#D8B4FE`
- Main text: `#F8F5FC`
- Secondary text: `#A99BBE`
- Success: `#4ADE80`
- Warning: `#F59E0B`
- Critical: `#EF4444`

Design direction: Apple-inspired premium minimalism with restrained purple glass surfaces, clear SOC information hierarchy, and Spartan brand identity.
