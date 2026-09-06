import { splitPath } from '../../lib/format';
import styles from './CodeEvidence.module.css';

interface CodeEvidenceProps {
  filePath: string;
  startLine: number | null;
  endLine?: number | null;
  snippet: string | null;
  /** The exact symbol the scanner matched, shown above the excerpt. */
  symbol?: string | null;
}

/**
 * Renders the evidence exactly as the API supplied it. The frontend never opens,
 * parses or re-analyses source files — `location.snippet` is the whole of what
 * QNetra saw at the discovery site.
 *
 * Line numbers are only shown for single-line excerpts, where `start_line` is
 * unambiguous. Multi-line excerpts are shown without a numbered gutter rather
 * than with numbers that might not correspond to the file.
 */
export function CodeEvidence({
  filePath,
  startLine,
  endLine,
  snippet,
  symbol,
}: CodeEvidenceProps) {
  const { dir, file } = splitPath(filePath);
  const lines = snippet ? snippet.replace(/\s+$/, '').split('\n') : [];
  const singleLine = lines.length === 1;

  return (
    <figure className={styles.figure}>
      <figcaption className={styles.caption}>
        <span className={`${styles.path} mono`}>
          <span className={styles.dir}>{dir}</span>
          <span className={styles.file}>{file}</span>
        </span>
        {startLine !== null && (
          <span className={`${styles.lineRef} mono numeric`}>
            {endLine && endLine !== startLine ? `L${startLine}–${endLine}` : `L${startLine}`}
          </span>
        )}
      </figcaption>

      {symbol && (
        <div className={styles.symbol}>
          <span className="eyebrow">Matched</span>
          <code className="mono">{symbol}</code>
        </div>
      )}

      {lines.length > 0 ? (
        <pre className={styles.code}>
          <code>
            {lines.map((line, index) => (
              <span className={styles.line} key={`${index}-${line}`}>
                {singleLine && startLine !== null && (
                  <span className={`${styles.gutter} numeric`}>{startLine}</span>
                )}
                {!singleLine && <span className={styles.gutterRule} aria-hidden="true" />}
                <span className={styles.lineText}>{line || ' '}</span>
              </span>
            ))}
          </code>
        </pre>
      ) : (
        <p className={styles.noSnippet}>
          The scanner did not retain a source excerpt for this location.
        </p>
      )}
    </figure>
  );
}

/** Compact file:line reference used inside table cells. */
export function PathRef({
  filePath,
  line,
}: {
  filePath: string;
  line?: number | null;
}) {
  const { dir, file } = splitPath(filePath);
  return (
    <span className={`${styles.pathRef} mono`} title={filePath}>
      <span className={styles.dir}>{dir}</span>
      <span className={styles.file}>{file}</span>
      {line !== null && line !== undefined && (
        <span className={`${styles.pathLine} numeric`}>:{line}</span>
      )}
    </span>
  );
}
