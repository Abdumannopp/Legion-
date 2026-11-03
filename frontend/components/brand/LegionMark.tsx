import { useId } from "react";

/**
 * The Legion helmet mark, drawn as vector geometry from the brand sheet:
 * a cube-shaped Spartan helmet — the top face is the crest, the two side
 * faces are the cheek guards, split by the nose guard.
 *
 * `variant="color"` is the violet gradient; `variant="mono"` uses
 * currentColor (white on dark, embossing, one-colour print).
 */

// The left half of the helmet; the right half is its mirror image.
const HALF =
  "M58 232 L438 455 L438 832 L406 832 L368 470 L168 434 L186 648 L300 718 " +
  "Q362 812 380 968 Q344 852 282 792 L100 668 Z";
const CREST_LEFT = "M445 55 L183 243 L445 398 Z";
const CREST_RIGHT = "M445 55 L707 243 L445 398 Z";
const MIRROR = "translate(890 0) scale(-1 1)";

export default function LegionMark({
  size = 32,
  variant = "color",
  className,
  title = "Legion",
}: {
  size?: number;
  variant?: "color" | "mono";
  className?: string;
  /** Accessible name; pass "" when the mark sits next to the word "Legion". */
  title?: string;
}) {
  // Gradient ids must be unique per instance, or two marks on one page
  // would share (and fight over) the same <defs>.
  const id = useId().replace(/:/g, "");
  const fill = (name: string) => (variant === "mono" ? "currentColor" : `url(#${name}${id})`);

  return (
    <svg
      viewBox="40 40 810 945"
      width={size}
      height={(size * 945) / 810}
      className={className}
      role={title ? "img" : undefined}
      aria-label={title || undefined}
      aria-hidden={title ? undefined : true}
      xmlns="http://www.w3.org/2000/svg"
    >
      {variant === "color" && (
        <defs>
          <linearGradient id={`lf${id}`} x1="0" y1="0" x2="0.55" y2="1">
            <stop offset="0" stopColor="#B89EFF" />
            <stop offset="0.55" stopColor="#8B5CF6" />
            <stop offset="1" stopColor="#6D28D9" />
          </linearGradient>
          <linearGradient id={`rf${id}`} x1="1" y1="0" x2="0.45" y2="1">
            <stop offset="0" stopColor="#8B5CF6" />
            <stop offset="0.6" stopColor="#6D28D9" />
            <stop offset="1" stopColor="#4C1D95" />
          </linearGradient>
          <linearGradient id={`dl${id}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#C4B0FF" />
            <stop offset="1" stopColor="#8B5CF6" />
          </linearGradient>
          <linearGradient id={`dr${id}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#7C3AED" />
            <stop offset="1" stopColor="#4C1D95" />
          </linearGradient>
        </defs>
      )}
      <path d={CREST_LEFT} fill={fill("dl")} />
      <path d={CREST_RIGHT} fill={fill("dr")} opacity={variant === "mono" ? 0.78 : 1} />
      <path d={HALF} fill={fill("lf")} />
      <path d={HALF} fill={fill("rf")} transform={MIRROR} opacity={variant === "mono" ? 0.88 : 1} />
    </svg>
  );
}
