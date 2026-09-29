import type { Config } from "tailwindcss";
import { palette as p } from "./lib/theme";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: p.canvas,
        panel: p.panel,
        surface: p.surface,
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
        success: p.success,
        info: p.info,
      },
      fontFamily: {
        // Wide geometric face from the logo, for brand, titles and labels.
        // Body text stays on the system font for readability.
        display: ["var(--font-display)", "var(--font-display-cyrillic)", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 24px -4px rgba(124, 58, 237, 0.45)",
      },
    },
  },
  plugins: [],
};
export default config;
