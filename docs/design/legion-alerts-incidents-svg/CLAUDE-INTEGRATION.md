# LEGION — Alerts & Incidents SVG Pack

## Included
- `alerts-incidents/legion-alerts-incidents.svg` — 1600×1000 scalable vector reference of the Alerts & Incidents screen.
- `CLAUDE-INTEGRATION.md` — implementation instructions.

## Claude integration
Use the SVG as a design reference, not as a static screenshot embedded in the product. Rebuild it as responsive, accessible React components in the existing Legion application.

1. Inspect current routes, alert/incident components, data hooks, API contracts, permissions and Wazuh integration before editing.
2. Implement severity KPI cards, Alerts/Incidents/Investigations/Response tabs, filters, list/table toggle, export affordance, selectable alert rows, pagination and a detail drawer.
3. Bind all displayed values and alert records to real API data. Numbers, IP addresses, timestamps, hosts, rule IDs and MITRE tags in this design reference are illustrative only; never ship them as real telemetry.
4. Keep severity semantics distinct: Critical red, High orange, Medium amber, Low blue. Purple is the brand/selection color, not a severity.
5. The drawer should show the selected alert's actual status, host, first/last seen, source/destination IP, port, protocol, description and ATT&CK mappings when available.
6. Implement Create Incident, Acknowledge and Mute only when supported by existing API permissions and contracts. Confirm destructive or consequential actions and show success/error states.
7. Preserve existing authentication, authorization, tenant isolation, routes, localization and backend behavior.
8. Add loading, empty, stale-data, partial-data, error and no-permission states. Do not invent missing data.
9. Make the layout responsive: collapse the sidebar and move the detail drawer to a mobile sheet on narrow screens; retain keyboard navigation and accessible labels.
10. Run frontend lint, tests, type-check and production build. Report any pre-existing failures separately.

## Visual tokens
- Canvas: `#090510`
- Panel: `#251638` / `#171024`
- Brand violet: `#A855F7`
- Lavender: `#D8B4FE`
- Main text: `#F8F5FC`
- Muted text: `#A99BBE`
- Critical: `#F87171`
- High: `#FB923C`
- Medium: `#FBBF24`
- Low: `#60A5FA`
- Healthy: `#4ADE80`

Brand lockup: LEGION — CYBERSECURITY INTELLIGENCE.
