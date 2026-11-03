/**
 * "LEGION" as drawn in the logo — wide geometric letters, the E without a
 * stem. Drawn as paths rather than set in a font so it looks identical
 * everywhere and needs no font file. Colour is currentColor.
 */
export default function LegionWordmark({
  height = 16,
  className,
  decorative = false,
}: {
  height?: number;
  className?: string;
  /** True when the text "Legion" is already provided nearby for screen readers. */
  decorative?: boolean;
}) {
  return (
    <svg
      viewBox="-4 -4 908 108"
      height={height}
      width={(height * 908) / 108}
      className={className}
      role={decorative ? undefined : "img"}
      aria-label={decorative ? undefined : "Legion"}
      aria-hidden={decorative || undefined}
      xmlns="http://www.w3.org/2000/svg"
    >
      <g fill="none" stroke="currentColor" strokeWidth={16} strokeLinejoin="round">
        <path d="M8 0 V92 H112" />
        <path d="M174 8 H274 M174 50 H274 M174 92 H274" />
        <path d="M456 8 H362 Q344 8 344 26 V74 Q344 92 362 92 H430 Q448 92 448 74 V56 H400" />
        <path d="M526 0 V100" />
        <rect x={604} y={8} width={108} height={84} rx={18} />
      </g>
      <path fill="currentColor" d="M782 100 V0 H802 L884 78 V0 H900 V100 H880 L798 22 V100 Z" />
    </svg>
  );
}
