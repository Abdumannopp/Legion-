# LEGION Login & Landing — SVG handoff

## Included files
- `login/legion-login.svg` — editable login-screen vector (1536 × 1024).
- `landing/legion-landing.svg` — editable landing-page vector (1648 × 1100).
- This guide — integration notes for Claude and the existing frontend.

## Design direction
Premium dark cybersecurity identity with violet neon accents, glass panels, Spartan shield mark, subtle global telemetry motifs, and restrained typography. Both pages share the same visual language.

## Integration instructions
1. Inspect the existing app structure and current routes before editing.
2. Use these SVGs as visual references or static previews; implement real responsive pages with the project's existing React/Next.js, TypeScript, and Tailwind patterns.
3. Preserve existing routing, auth/session logic, API clients, design tokens, navigation, and shared components. Do not replace the working app with static SVGs.
4. Login: connect the form to the existing authentication provider. Implement validation, password visibility, loading, error, MFA/SSO states as supported by the backend. The social sign-in marks in the SVG are visual placeholders; only show providers that are actually configured.
5. Landing: wire Get Started, Explore Platform, navigation, language selection, and pricing links to real routes or actions. Do not invent product capabilities, integrations, certifications, customer logos, or performance claims.
6. Use the existing LEGION logo asset if one exists; otherwise the stylized shield in the SVG is a visual placeholder.
7. Rebuild the layout responsively. On mobile, simplify the hero illustration, stack feature cards, and make the login panel fit narrow screens without horizontal scrolling.
8. Ensure keyboard navigation, semantic form labels, accessible contrast, visible focus states, and screen-reader feedback.
9. Keep secrets and authentication tokens out of client-side source and logs.

## Important content notes
- The SOC dashboard preview and all metrics shown on the landing SVG are illustrative visual placeholders, not live telemetry.
- The copyright year and labels are sample copy; update them to the actual product/legal wording.
- The decorative Spartan helmet and shield should not be treated as a substitute for the official brand logo.

## Suggested components
- `LoginPage`, `LoginForm`, `SocialSignInOptions`, `ForgotPasswordLink`
- `LandingPage`, `SiteHeader`, `HeroSection`, `CapabilityOrbit`, `FeatureCards`, `SocPreview`

## Acceptance checklist
- [ ] Existing auth/session flow remains intact and works end-to-end.
- [ ] Form validation, loading, error, and MFA states are accessible.
- [ ] SSO buttons appear only for configured identity providers.
- [ ] Landing CTAs and navigation resolve to real destinations.
- [ ] No invented metrics or unsupported product claims are presented as factual.
- [ ] Responsive desktop, tablet, and mobile layouts work.
- [ ] SVG placeholders are replaced with approved brand assets where available.
