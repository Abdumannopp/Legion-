/**
 * LEGION Global Design System — Premium Dark
 * Source of truth for brand, semantic, surface, typography, spacing and motion tokens.
 * Keep severity colors semantically separate from the violet brand.
 */
export const tokens = {
  color: {
    brand: {
      violet: "#8B5CF6",
      violetStrong: "#7C3AED",
      violetDeep: "#5B21B6",
      lavender: "#C4B5FD",
      lilac: "#E9D5FF",
      glow: "rgba(168, 85, 247, 0.22)",
    },
    background: {
      canvas: "#08060F",
      sidebar: "#0B0813",
      elevated: "#100B1B",
      surface: "#151020",
      surfaceRaised: "#1C1429",
      surfaceHover: "#241934",
      glass: "rgba(28, 20, 41, 0.72)",
    },
    border: {
      subtle: "rgba(196, 181, 253, 0.10)",
      default: "rgba(196, 181, 253, 0.16)",
      strong: "rgba(196, 181, 253, 0.26)",
      focus: "#A78BFA",
    },
    text: {
      primary: "#F8F7FC",
      secondary: "#D5CDE2",
      muted: "#A99DBB",
      subtle: "#817591",
      disabled: "#5E566B",
      inverse: "#120D1B",
    },
    status: {
      critical: "#F87171",
      high: "#FB923C",
      medium: "#FBBF24",
      low: "#60A5FA",
      healthy: "#4ADE80",
      info: "#67C7F5",
      unknown: "#A1A1AA",
    },
  },
  typography: {
    fontSans: 'Inter, -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", sans-serif',
    fontMono: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
    size: { xs: "0.6875rem", sm: "0.8125rem", base: "0.9375rem", lg: "1.0625rem", xl: "1.25rem", "2xl": "1.5rem", "3xl": "2rem" },
    lineHeight: { tight: 1.15, normal: 1.5, relaxed: 1.65 },
    weight: { regular: 400, medium: 500, semibold: 600, bold: 700 },
  },
  radius: { sm: "0.625rem", md: "0.875rem", lg: "1.125rem", xl: "1.375rem", "2xl": "1.75rem", pill: "999px" },
  spacing: { pageX: "clamp(1rem, 2.2vw, 2rem)", section: "1.5rem", card: "1.125rem", control: "0.75rem" },
  shadow: {
    card: "0 12px 36px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.035)",
    floating: "0 22px 70px rgba(0,0,0,.42)",
    violet: "0 0 28px rgba(139,92,246,.20)",
    focus: "0 0 0 3px rgba(167,139,250,.24)",
  },
  motion: {
    fast: "140ms cubic-bezier(.2,.8,.2,1)",
    normal: "220ms cubic-bezier(.2,.8,.2,1)",
    slow: "360ms cubic-bezier(.2,.8,.2,1)",
  },
} as const;

export type LegionTokens = typeof tokens;
