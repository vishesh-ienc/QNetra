import type { SeverityTone } from '../../lib/labels';
import styles from './ScoreDial.module.css';

interface ScoreDialProps {
  /** Backend-computed score. Never derived in the frontend. */
  score: number | null;
  max?: number;
  label: string;
  caption?: string;
  tone?: SeverityTone;
  size?: number;
}

/**
 * One score, rendered once per page at most. The arc is a reading aid for a number
 * the backend computed — it adds no information of its own.
 */
export function ScoreDial({
  score,
  max = 100,
  label,
  caption,
  tone = 'ACCENT',
  size = 176,
}: ScoreDialProps) {
  const radius = size / 2 - 8;
  const circumference = Math.PI * radius; // half circle
  const ratio = score === null ? 0 : Math.max(0, Math.min(1, score / max));
  const offset = circumference * (1 - ratio);
  const centre = size / 2;

  return (
    <div className={styles.dial} data-sev={tone} style={{ width: size }}>
      <svg
        width={size}
        height={size / 2 + 12}
        viewBox={`0 0 ${size} ${size / 2 + 12}`}
        role="img"
        aria-label={
          score === null ? `${label}: not available` : `${label}: ${score} out of ${max}`
        }
      >
        <path
          d={`M 8 ${centre} A ${radius} ${radius} 0 0 1 ${size - 8} ${centre}`}
          fill="none"
          stroke="var(--surface-3)"
          strokeWidth="6"
          strokeLinecap="round"
        />
        {score !== null && (
          <path
            className={styles.arc}
            d={`M 8 ${centre} A ${radius} ${radius} 0 0 1 ${size - 8} ${centre}`}
            fill="none"
            stroke="var(--sev)"
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        )}
      </svg>
      <div className={styles.readout}>
        {score === null ? (
          <p className={styles.unavailable}>Not available</p>
        ) : (
          <p className={`${styles.score} numeric`}>
            {Number.isInteger(score) ? score : score.toFixed(1)}
            <span className={styles.max}>/{max}</span>
          </p>
        )}
        <p className={styles.label}>{label}</p>
      </div>
      {caption && <p className={styles.caption}>{caption}</p>}
    </div>
  );
}
