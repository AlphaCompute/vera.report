import Link from "next/link";

interface VeraLogoProps {
  subtitle?: string;
  size?: "sm" | "md" | "lg" | "hero";
  linked?: boolean;
}

export function VeraLogo({ subtitle, size = "md", linked = true }: VeraLogoProps) {
  const sizeConfig = {
    sm: { vera: "18px", spacing: "0.28em", sub: "8px", subSpacing: "0.3em", line: 20, lineGap: "5px", subGap: "3px" },
    md: { vera: "24px", spacing: "0.28em", sub: "9px", subSpacing: "0.35em", line: 28, lineGap: "6px", subGap: "4px" },
    lg: { vera: "36px", spacing: "0.3em", sub: "10px", subSpacing: "0.35em", line: 36, lineGap: "8px", subGap: "5px" },
    hero: { vera: "clamp(4.5rem, 13vw, 11rem)", spacing: "0.18em", sub: "12px", subSpacing: "0.85em", line: 48, lineGap: "28px", subGap: "clamp(2px, 0.4vw, 6px)" },
  };

  const cfg = sizeConfig[size];
  const isHero = size === "hero";

  const content = (
    <div className={`flex flex-col items-center select-none ${isHero ? "inline-flex" : ""}`}>
      {/* VERA wordmark */}
      <span
        className="font-serif text-white/90 block"
        style={{
          fontSize: cfg.vera,
          fontWeight: 400,
          letterSpacing: cfg.spacing,
          lineHeight: 1,
          textTransform: "uppercase",
          ...(isHero ? { marginRight: `-${cfg.spacing}` } : {}),
        }}
      >
        V
        <span className="relative">
          <span className="relative" style={{ color: "rgba(255,255,255,0.92)" }}>E</span>
        </span>
        RA
      </span>

      {/* Subtitle — placed right below VERA for hero, with line underneath */}
      {subtitle && isHero ? (
        <>
          <span
            className="text-white/40 block text-center"
            style={{
              marginTop: cfg.subGap,
              fontSize: cfg.sub,
              textTransform: "uppercase",
              fontWeight: 300,
              letterSpacing: cfg.subSpacing,
            }}
          >
            {subtitle}
          </span>
          <div
            className="mx-auto"
            style={{
              width: cfg.line,
              height: 1,
              marginTop: cfg.lineGap,
              background: "linear-gradient(90deg, transparent, #3d8b8b, transparent)",
            }}
          />
        </>
      ) : (
        <>
          {/* Teal accent line (non-hero) */}
          <div
            className="mx-auto"
            style={{
              width: cfg.line,
              height: 1,
              marginTop: cfg.lineGap,
              background: "linear-gradient(90deg, transparent, #3d8b8b, transparent)",
            }}
          />
          {/* Subtitle (non-hero) */}
          {subtitle && (
            <span
              className="block text-white/40"
              style={{
                fontSize: cfg.sub,
                letterSpacing: cfg.subSpacing,
                textTransform: "uppercase",
                marginTop: cfg.subGap,
                fontWeight: 300,
              }}
            >
              {subtitle}
            </span>
          )}
        </>
      )}
    </div>
  );

  if (linked) {
    return (
      <Link href="/" className="hover:opacity-80 transition-opacity">
        {content}
      </Link>
    );
  }

  return content;
}