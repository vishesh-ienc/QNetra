import type { SeverityTone } from '../../lib/labels';
import styles from './Meter.module.css';

interface MeterProps {
  /** 0–1. Presentation width only, derived from backend counts. */
  value: number;
  tone?: SeverityTone;
  label?: string;
  size?: 'sm' | 'md';
}

export function Meter({ value, tone = 'ACCENT', label, size = 'md' }: MeterProps) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div
      className={`${styles.track} ${styles[size]}`}
      data-sev={tone}
      role="img"
      aria-label={label ?? `${pct.toFixed(0)} percent`}
    >
      <div className={styles.fill} style={{ width: `${pct}%` }} />
    </div>
  );
}

export interface DistributionSegment {
  key: string;
  label: string;
  count: number;
  tone: SeverityTone;
}

/**
 * A single proportional bar. One bar communicates a distribution better than four
 * separate mini-charts, and stays readable at any width.
 */
export function DistributionBar({
  segments,
  total,
}: {
  segments: DistributionSegment[];
  total: number;
}) {
  const visible = segments.filter((s) => s.count > 0);
  if (!total || visible.length === 0) {
    return <div className={`${styles.track} ${styles.md} ${styles.empty}`} />;
  }
  return (
    <div className={styles.distribution}>
      {visible.map((segment) => (
        <div
          key={segment.key}
          className={styles.segment}
          data-sev={segment.tone}
          style={{ flexGrow: segment.count }}
          title={`${segment.label}: ${segment.count.toLocaleString()}`}
        />
      ))}
    </div>
  );
}
