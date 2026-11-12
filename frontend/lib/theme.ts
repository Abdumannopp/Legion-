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
  // Surfaces, darkest to lightest (Legion global design system, premium dark)
  canvas: "#08060F", // page background
  panel: "#100B1B", // inputs, inner panels, sidebar
  surface: "#151020", // cards
  raised: "#1C1429", // raised cards, selected rows
  hover: "#241934", // hover on surfaces
  line: "#312A43", // borders, dividers (lavender at 16 % on a card)
  lineStrong: "#423B59",

  // Text
  ink: "#F8F7FC",
  inkSoft: "#D5CDE2",
  inkMuted: "#A99DBB",
  inkFaint: "#817591",
  inkDisabled: "#5E566B",

  // Brand: violet for brand, selection and primary actions — never for severity
  brand: "#7C3AED", // solid fills: primary buttons, active pills
  brandHover: "#8B5CF6",
  brandBright: "#C4B5FD", // lavender: violet text and icons on dark backgrounds
  brandDeep: "#5B21B6",

  // Meaning, independent of the brand
  critical: "#F87171",
  criticalHover: "#FCA5A5",
  high: "#FB923C",
  warning: "#FBBF24", // also "medium" severity
  low: "#60A5FA",
  success: "#4ADE80", // healthy
  info: "#67C7F5",
} as const;

/** One severity scale for every screen: critical red, high orange, medium amber, low blue. */
export const severityColor = {
  critical: palette.critical,
  high: palette.high,
  medium: palette.warning,
  low: palette.low,
} as const;

export type PaletteColor = keyof typeof palette;
