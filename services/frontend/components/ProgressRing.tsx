'use client';

const SIZE = 72;
const STROKE = 6;
const R = (SIZE - STROKE) / 2;
const C = SIZE / 2;
const CIRCUMFERENCE = 2 * Math.PI * R;

export function ProgressRing({ value, max = 100, className = '' }: { value: number; max?: number; className?: string }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  const offset = CIRCUMFERENCE - (pct / 100) * CIRCUMFERENCE;
  return (
    <svg width={SIZE} height={SIZE} className={`progress-ring ${className}`} aria-hidden>
      <circle className="progress-ring-bg" cx={C} cy={C} r={R} />
      <circle
        className="progress-ring-fill"
        cx={C}
        cy={C}
        r={R}
        strokeDasharray={CIRCUMFERENCE}
        strokeDashoffset={offset}
      />
    </svg>
  );
}
