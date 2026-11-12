# LEGION — Cybersecurity Intelligence Logo Pack

A scalable SVG identity pack for the LEGION cybersecurity platform.

## Files
- `brand/legion-horizontal.svg` — primary horizontal lockup for desktop headers and website navigation.
- `brand/legion-stacked.svg` — centered lockup for login screens, splash screens and presentations.
- `brand/legion-mark.svg` — symbol-only transparent mark for compact sidebar and app contexts.
- `brand/legion-favicon.svg` — square dark favicon/app icon.

## Integration notes for Claude
1. Copy the `brand` folder into `frontend/public/brand/`.
2. Use `/brand/legion-horizontal.svg` for desktop brand headers.
3. Use `/brand/legion-mark.svg` in compact sidebar/mobile contexts.
4. Use `/brand/legion-stacked.svg` on login/marketing hero sections where appropriate.
5. Set `/brand/legion-favicon.svg` as the favicon if the framework supports SVG icons.
6. Preserve aspect ratio (`width: auto; height: auto; max-width: 100%`). Do not stretch.
7. Keep the transparent SVG backgrounds transparent; only the favicon includes its own dark rounded-square background.
8. Replace old visible tagline with exactly `CYBERSECURITY INTELLIGENCE`.
9. Keep all existing routes, layout behavior, theme tokens and functionality unchanged.
10. Verify desktop and mobile layouts, then run lint, type-check and production build.

## Design system
- Deep background: `#090510`
- Purple: `#A855F7`
- Violet: `#6D28D9`
- Highlight: `#E9D5FF`
- Wordmark: white / soft white
- Tagline: `#D8D2E2`

The SVG wordmark uses a system sans-serif stack. For brand-critical print production, convert text to outlines in a vector editor after selecting the final licensed typeface.
