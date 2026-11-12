import type { Config } from "tailwindcss";
import { palette as p } from "./lib/theme";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  // Built from a value at runtime (`lg-status-${severity}`), so Tailwind cannot see them in the source.
  safelist: ["lg-status-critical", "lg-status-high", "lg-status-medium", "lg-status-low", "lg-status-healthy", "lg-status-brand"],
  theme: {
    extend: {
      colors: {
        canvas: p.canvas,
        panel: p.panel,
        surface: { DEFAULT: p.surface, raised: p.raised, hover: p.hover },
        line: { DEFAULT: p.line, strong: p.lineStrong },
        ink: {
          DEFAULT: p.ink,
          soft: p.inkSoft,
          muted: p.inkMuted,
          faint: p.inkFaint,
          disabled: p.inkDisabled,
        },
        brand: {
          DEFAULT: p.brand,
          hover: p.brandHover,
          bright: p.brandBright,
          deep: p.brandDeep,
        },
        critical: { DEFAULT: p.critical, hover: p.criticalHover },
        warning: p.warning,
        high: p.high,
        low: p.low,
        success: p.success,
        info: p.info,
      },
      fontFamily: {
        // Wide geometric face from the logo, for brand, titles and labels.
        // Body text stays on the system font for readability.
        display: ["var(--font-display)", "var(--font-display-cyrillic)", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      borderRadius: { "lg-sm": "10px", "lg-md": "14px", "lg-lg": "18px", "lg-xl": "22px" },
      boxShadow: {
        glow: "0 0 24px -4px rgba(124, 58, 237, 0.45)",
        card: "0 12px 36px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.035)",
        float: "0 22px 70px rgba(0,0,0,.42)",
        violet: "0 0 28px rgba(139,92,246,.20)",
      },
    },
  },
  plugins: [],
};
export default config;
