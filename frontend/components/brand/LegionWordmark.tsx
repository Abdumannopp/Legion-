/**
 * "LEGION" as set in the official logo (public/brand/legion-cybersecurity-intelligence.svg): heavy sans-serif
 * capitals, wide letter-spacing. Colour is currentColor.
 */
export default function LegionWordmark({
  height = 16,
  className,
  decorative = false,
}: {
  /** Cap height in px, roughly. */
  height?: number;
  className?: string;
  /** True when the text "Legion" is already provided nearby for screen readers. */
  decorative?: boolean;
}) {
  // The logo's wordmark box: 112 px type with 12 px tracking, about 560 × 84 of ink.
  return (
    <svg
      viewBox="0 0 560 84"
      height={height}
      width={(height * 560) / 84}
      className={className}
      role={decorative ? undefined : "img"}
      aria-label={decorative ? undefined : "Legion"}
      aria-hidden={decorative || undefined}
      xmlns="http://www.w3.org/2000/svg"
    >
      <text x="0" y="82" fill="currentColor" fontFamily="Arial, Helvetica, sans-serif" fontSize="112" fontWeight="800" letterSpacing="12" textLength="552" lengthAdjust="spacingAndGlyphs">
        {/* i18n-ignore: brand name */}
        LEGION
      </text>
    </svg>
  );
}
