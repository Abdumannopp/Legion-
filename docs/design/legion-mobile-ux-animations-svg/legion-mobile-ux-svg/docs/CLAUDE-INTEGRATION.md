# LEGION Mobile UX & Animations — SVG handoff

## Included
- `mobile-ux/legion-mobile-ux-animations.svg` — editable vector showcase (1536 × 1024).
- This guide — implementation notes for Claude and the existing frontend.

## Screens represented
- Onboarding / splash
- Mobile sign-in
- SOC dashboard with health gauge and metrics
- Alerts list with severity filters
- Incident detail with AI summary and recommended action
- UX motion patterns and critical push notification

## Integration guidance
1. Inspect the existing mobile/responsive app architecture and routes before editing.
2. Use the SVG as a visual reference, not as the shipped interactive application. Rebuild each screen with the project's existing React/Next.js or mobile framework, TypeScript, and component conventions.
3. Preserve existing authentication, authorization, API clients, route guards, tenant isolation, and design tokens.
4. Prioritize responsive web behavior if this is a web app; if a native app exists, follow its current navigation and platform conventions.
5. Wire dashboard metrics, alert counts, incident details, AI summaries, and notification payloads to authorized live APIs. All values in this SVG are illustrative placeholders, not live telemetry.
6. Implement animation as purposeful state transitions: loading skeleton/spinner, success confirmation, error feedback, new-alert pulse, live-data refresh, swipe actions, and expand/collapse. Respect reduced-motion preferences and avoid excessive continuous movement.
7. Swipe actions must have an accessible button/menu alternative. Never make a gesture the only way to complete an action.
8. Push notifications must use the real notification service and user consent/preferences. Do not simulate delivery in production.
9. Security actions such as host isolation must require explicit confirmation and backend authorization; an AI recommendation alone must never execute an action.
10. Test small screens, safe areas, keyboard behavior, screen readers, touch targets, and both light/dark system accessibility settings if supported.

## UX / accessibility checklist
- [ ] Touch targets are comfortably sized and spaced.
- [ ] Bottom navigation remains reachable and does not cover content.
- [ ] Lists support loading, empty, error, and pagination states.
- [ ] Critical severity is conveyed with text/icon, not color alone.
- [ ] Motion honors `prefers-reduced-motion` / platform reduced-motion settings.
- [ ] Swipe actions have visible accessible alternatives.
- [ ] Notifications respect opt-in and per-category preferences.
- [ ] Sensitive incident details are protected by existing auth/session controls.
- [ ] No sample values are presented as real security telemetry.

## Suggested component breakdown
- `MobileOnboarding`
- `MobileLogin`
- `MobileSocDashboard`
- `MobileBottomNavigation`
- `MobileAlertList`
- `MobileIncidentDetail`
- `MotionFeedback`
- `PushNotificationPreview`
