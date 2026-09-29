/**
 * Legion's colour palette, taken from the logo: a near-black with a violet
 * cast, and the violet gradient of the helmet mark.
 *
 * One source of truth: tailwind.config.ts builds its colour tokens from this
 * object (`bg-surface`, `text-ink-muted`, `border-line`, `bg-brand` …), and
 * code that needs a colour at runtime (inline styles, icon `color` props,
 * charts) imports `palette` instead of hard-coding a hex value.
 *
 * Severity colours are deliberately NOT the brand colour. "Medium" used to
 * share the primary blue; with a violet brand that would make a medium alert
 * look like a button. Severity keeps its own, conventional scale.
 */
export const palette = {
  // Surfaces, darkest to lightest
  canvas: "#08060F", // page background
  panel: "#0E0A19", // inputs, inner panels, sidebar accents
  surface: "#140F24", // cards
  line: "#251C3D", // borders, dividers
  lineStrong: "#342A4F",

  // Text
  ink: "#F6F4FB",
  inkSoft: "#D9D3EA",
  inkMuted: "#B1A9CC",
  inkFaint: "#857CA8",
  inkDisabled: "#4F4669",

  // Brand (the helmet gradient runs brandBright → brand → brandDeep)
  brand: "#7C3AED", // solid fills: primary buttons, active pills
  brandHover: "#8B5CF6",
  brandBright: "#A78BFA", // violet text and icons on dark backgrounds
  brandDeep: "#5B21B6",

  // Meaning, independent of the brand
  critical: "#EF4444",
  criticalHover: "#F05252",
  warning: "#F59E0B",
  success: "#22C55E",
  info: "#38BDF8",
} as const;

export type PaletteColor = keyof typeof palette;
