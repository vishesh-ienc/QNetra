import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScanContext } from '../state/useScanContext';
import styles from './LandingPage.module.css';

export function LandingPage() {
  const navigate = useNavigate();
  const { hasResults } = useScanContext();

  useEffect(() => {
    if (hasResults) {
      navigate('/posture', { replace: true });
    }
  }, [hasResults, navigate]);

  return (
    <section className={styles.hero} aria-label="QNetra welcome">
      {/* Eyebrow */}
      <div className={styles.eyebrow}>
        <span className={styles.eyebrowDot} aria-hidden="true" />
        Post-Quantum Cryptography Intelligence
      </div>

      {/* Wordmark */}
      <h1 className={styles.wordmark}>QNetra</h1>

      {/* Description */}
      <p className={styles.desc}>
        <strong>Discover, analyze, and migrate</strong> every cryptographic asset in your codebase.
        QNetra gives you a full CBOM, quantum-risk exposure scores, and a prioritized PQC migration plan � in minutes.
      </p>

      {/* CTA */}
      <div className={styles.ctaWrap}>
        <button
          id="landing-scan-now"
          type="button"
          className={styles.cta}
          onClick={() => navigate('/scan')}
        >
          Start a Scan
          <span className={styles.ctaArrow} aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </span>
        </button>
        <span className={styles.ctaHint}>No account required &middot; Upload any artifact</span>
      </div>

      {/* Stats strip */}
      <div className={styles.statsRow} aria-label="Platform highlights">
        <div className={styles.stat}>
          <span className={styles.statValue}>40+</span>
          <span className={styles.statLabel}>Crypto algorithms</span>
        </div>
        <div className={styles.statDivider} aria-hidden="true" />
        <div className={styles.stat}>
          <span className={styles.statValue}>CBOM</span>
          <span className={styles.statLabel}>CycloneDX output</span>
        </div>
        <div className={styles.statDivider} aria-hidden="true" />
        <div className={styles.stat}>
          <span className={styles.statValue}>PQC</span>
          <span className={styles.statLabel}>Migration ready</span>
        </div>
        <div className={styles.statDivider} aria-hidden="true" />
        <div className={styles.stat}>
          <span className={styles.statValue}>Mosca</span>
          <span className={styles.statLabel}>HNDL urgency</span>
        </div>
      </div>
    </section>
  );
}
