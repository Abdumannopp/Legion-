import { useId } from "react";

/**
 * The Legion emblem: the purple Spartan helmet inside a shield (public/brand/legion-mark.svg, from the premium
 * brand pack). In colour it is the brand file itself, so every screen shows exactly the approved artwork with a
 * transparent background; `variant="mono"` is a one-colour silhouette in currentColor for embossing and print.
 */
export default function LegionMark({
  size = 32,
  variant = "color",
  className,
  title = "Legion",
}: {
  /** Width in px; the height follows the emblem's proportions. */
  size?: number;
  variant?: "color" | "mono";
  className?: string;
  /** Accessible name; pass "" when the mark sits next to the word "Legion". */
  title?: string;
}) {
  // Gradient and filter ids must be unique per instance, or two marks on one page would share them.
  const id = useId().replace(/:/g, "");
  const mono = variant === "mono";
  if (!mono) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img
        src="/brand/legion-mark.svg"
        width={size}
        height={Math.round((size * 360) / 320)}
        alt={title}
        aria-hidden={title ? undefined : true}
        className={className}
        draggable={false}
      />
    );
  }
  const g = (name: string) => (mono ? "currentColor" : `url(#${name}${id})`);
  return (
    <svg
      viewBox="14 0 312 360"
      width={size}
      height={(size * 360) / 312}
      className={className}
      role={title ? "img" : undefined}
      aria-label={title || undefined}
      aria-hidden={title ? undefined : true}
      xmlns="http://www.w3.org/2000/svg"
    >
      {!mono && (
        <defs>
          <linearGradient id={`violet${id}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#E5B8FF" />
            <stop offset=".42" stopColor="#A855F7" />
            <stop offset="1" stopColor="#6D28D9" />
          </linearGradient>
          <linearGradient id={`helmet${id}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#DCC4FF" />
            <stop offset=".48" stopColor="#8B5CF6" />
            <stop offset="1" stopColor="#3B0764" />
          </linearGradient>
          <filter id={`glow${id}`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
      )}
      <path d="M170 8 L316 67 L307 207 Q296 278 170 350 Q44 278 33 207 L24 67 Z" fill="none" stroke={g("violet")} strokeWidth="13" strokeLinejoin="round" />
      <path d="M170 40 Q116 74 91 123 L91 211 L137 280 L170 315 L203 280 L249 211 L249 123 Q224 74 170 40Z" fill={mono ? "none" : "#10071D"} stroke={g("helmet")} strokeWidth="5" strokeLinejoin="round" />
      <path d="M170 43 L170 188 L104 151 L111 204 L146 228 L146 285 L170 315Z" fill={g("helmet")} opacity=".96" />
      <path d="M170 43 L170 188 L236 151 L229 204 L194 228 L194 285 L170 315Z" fill={mono ? "currentColor" : "#4C1D95"} opacity={mono ? 0.7 : 0.88} />
      {!mono && (
        <>
          <path d="M170 43 L170 188 L104 151 L111 204 L146 228 L146 285" fill="none" stroke="#E9D5FF" strokeOpacity=".72" strokeWidth="3" strokeLinejoin="round" />
          <path d="M170 43 L170 188 L236 151 L229 204 L194 228 L194 285" fill="none" stroke="#A855F7" strokeOpacity=".9" strokeWidth="3" strokeLinejoin="round" />
        </>
      )}
      <path d="M104 151 L151 174 L170 191 L189 174 L236 151 L229 188 L190 211 L170 213 L150 211 L111 188Z" fill={mono ? "currentColor" : "#090510"} opacity={mono ? 0.35 : 1} />
      <path d="M118 169 L157 185 L145 190 L126 183Z M222 169 L183 185 L195 190 L214 183Z" fill={mono ? "currentColor" : "#F5E9FF"} filter={mono ? undefined : `url(#glow${id})`} />
      {!mono && <path d="M170 214 L170 315" stroke="#D8B4FE" strokeWidth="3" opacity=".7" />}
    </svg>
  );
}
