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
  // Surfaces, darkest to lightest — Apple-style dark: true black, system grays, hairline borders
  canvas: "#000000", // page background
  panel: "#0E0E10", // inputs, inner panels, sidebar
  surface: "#1C1C1E", // cards
  raised: "#2C2C2E", // raised cards, selected rows
  hover: "#3A3A3C", // hover on surfaces
  line: "#2E2E33", // borders, dividers (hairline)
  lineStrong: "#48484A",

  // Text
  ink: "#F5F5F7",
  inkSoft: "#D1D1D6",
  inkMuted: "#A1A1A6",
  inkFaint: "#8E8E93",
  inkDisabled: "#636366",

  // Brand: violet for brand, selection and primary actions — never for severity
  brand: "#7D52F4", // solid fills: primary buttons, active pills
  brandHover: "#8F6AF7",
  brandBright: "#C9B8FF", // lavender: violet text and icons on dark backgrounds
  brandDeep: "#5B21B6",

  // Meaning, independent of the brand (Apple system colours, dark appearance)
  critical: "#FF453A",
  criticalHover: "#FF6961",
  high: "#FF9F0A",
  warning: "#FFD60A", // also "medium" severity
  low: "#0A84FF",
  success: "#30D158", // healthy
  info: "#64D2FF",
} as const;

/** One severity scale for every screen: critical red, high orange, medium amber, low blue. */
export const severityColor = {
  critical: palette.critical,
  high: palette.high,
  medium: palette.warning,
  low: palette.low,
} as const;

export type PaletteColor = keyof typeof palette;
