import LegionMark from "./LegionMark";
import LegionWordmark from "./LegionWordmark";

/**
 * The two lock-ups from the brand sheet.
 *
 *  - "stacked":    emblem above, LEGION, CYBERSECURITY INTELLIGENCE — sign-in, setup.
 *  - "horizontal": mark | divider | LEGION over the tagline — headers.
 */
export default function LegionLogo({
  layout = "horizontal",
  size = 36,
  tagline = true,
  className = "",
}: {
  layout?: "horizontal" | "stacked";
  /** Height of the mark in px; everything else scales from it. */
  size?: number;
  tagline?: boolean;
  className?: string;
}) {
  const markWidth = (size * 320) / 360;

  if (layout === "stacked") {
    return (
      <div className={`flex flex-col items-center ${className}`}>
        <LegionMark
          size={markWidth}
          title=""
          className="drop-shadow-[0_0_28px_rgba(124,58,237,0.35)]"
        />
        <LegionWordmark decorative height={size * 0.3} className="text-ink mt-[0.45em]" />
        {tagline && (
          <span
            aria-hidden
            className="font-display text-brand-bright uppercase whitespace-nowrap"
            style={{ fontSize: size * 0.1, letterSpacing: "0.3em", marginTop: size * 0.12, marginRight: "-0.3em" }}
          >
            {/* i18n-ignore: logo lockup, a brand mark */}
            Cybersecurity Intelligence
          </span>
        )}
        <span
          aria-hidden
          className="block h-px bg-gradient-to-r from-transparent via-brand-hover to-transparent opacity-70"
          style={{ width: size * 1.2, marginTop: size * 0.14 }}
        />
        {/* i18n-ignore: brand name */}
      <span className="sr-only">Legion Cybersecurity Intelligence</span>
      </div>
    );
  }

  return (
    <div className={`flex items-center ${className}`} style={{ gap: size * 0.3 }}>
      <LegionMark size={markWidth} title="" className="shrink-0 drop-shadow-[0_0_10px_rgba(124,58,237,0.35)]" />
      <span aria-hidden className="self-stretch w-px bg-line-strong" />
      <span className="flex flex-col justify-center">
        <LegionWordmark decorative height={size * 0.34} className="text-ink" />
        {tagline && (
          <span
            aria-hidden
            className="font-display text-brand-bright uppercase whitespace-nowrap"
            style={{ fontSize: Math.max(7, size * 0.17), letterSpacing: "0.3em", marginTop: size * 0.12 }}
          >
            {/* i18n-ignore: logo lockup, a brand mark */}
            Cybersecurity Intelligence
          </span>
        )}
      </span>
      {/* i18n-ignore: brand name */}
      <span className="sr-only">Legion Cybersecurity Intelligence</span>
    </div>
  );
}

/**
 * The official logo file itself (emblem, LEGION, CYBERSECURITY INTELLIGENCE), for places with room for it.
 * It keeps its proportions (1200 × 420) and a transparent background; the tagline is legible from about 360 px wide.
 */
export function LegionLockup({ width = 420, className = "" }: { width?: number; className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src="/brand/legion-horizontal.svg"
      // i18n-ignore: brand name
      alt="Legion — Cybersecurity Intelligence"
      width={width}
      height={Math.round((width * 420) / 1200)}
      className={`max-w-full h-auto ${className}`}
      draggable={false}
    />
  );
}
