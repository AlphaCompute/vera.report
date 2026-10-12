/** Site ink at a given strength; follows light and dark themes (globals.css). */
export const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;
