import { NavLink } from 'react-router-dom';
import { useScanContext } from '../../state/useScanContext';
import type { PipelineStage } from '../../api/types';
import { NAV } from './nav';
import styles from './SideNav.module.css';

export function SideNav({ onNavigate }: { onNavigate?: () => void }) {
  const { hasResults, scan } = useScanContext();

  const isScanning = scan?.status === 'RUNNING' || scan?.status === 'QUEUED';

  // The ordered pipeline — used to determine if a nav stage is currently active
  const STAGE_ORDER: PipelineStage[] = [
    'QUEUED', 'ACQUISITION', 'DISCOVERY', 'NORMALIZATION', 'CLASSIFICATION',
    'RISK_ANALYSIS', 'MOSCA_ANALYSIS', 'PQC_ANALYSIS', 'CBOM', 'COMPLETED',
  ];

  function stageIdx(s: string) {
    const i = STAGE_ORDER.indexOf(s as PipelineStage);
    return i === -1 ? 0 : i;
  }

  const currentIdx = stageIdx(scan?.current_stage ?? '');

  /** True if a nav item's required stage is the one currently running. */
  function isStageActive(requiredStage?: PipelineStage): boolean {
    if (!isScanning || !requiredStage) return false;
    return scan?.current_stage === requiredStage;
  }

  /** True if a nav item's required stage has not been reached yet. */
  function isStagePending(requiredStage?: PipelineStage): boolean {
    if (hasResults || !isScanning || !requiredStage) return false;
    return stageIdx(requiredStage) > currentIdx;
  }

  return (
    <nav className={styles.nav} aria-label="Primary">
      <NavLink to="/" className={styles.brand} onClick={onNavigate}>
        <svg viewBox="0 0 32 32" className={styles.mark} aria-hidden="true">
          <circle cx="16" cy="16" r="8.5" fill="none" stroke="currentColor" strokeWidth="2.2" />
          <path d="M18.5 18.5 L24 24" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" />
          <circle cx="16" cy="16" r="2.6" fill="currentColor" />
        </svg>
        <span className={styles.brandText}>
          <span className={styles.brandName}>QNetra</span>
          <span className={styles.brandSub}>Cryptographic Intelligence</span>
        </span>
      </NavLink>

      <div className={styles.groups}>
        {NAV.map((group) => (
          <div className={`${styles.group} ${group.unlabeled ? styles.groupUnlabeled : ''}`} key={group.label}>
            {!group.unlabeled && <p className={styles.groupLabel}>{group.label}</p>}
            <ul>
              {group.items.map((item) => {
                const isHistoryItem = Boolean(item.isHistory);
                const active    = !isHistoryItem && isStageActive(item.requiredStage as PipelineStage | undefined);
                const pending   = !isHistoryItem && (
                  isStagePending(item.requiredStage as PipelineStage | undefined)
                  || (Boolean(item.needsResults) && !hasResults && !isScanning)
                );
                const isComplete = !isHistoryItem && Boolean(item.needsResults) && hasResults;
                return (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.to === '/'}
                      title={item.question}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        [
                          styles.link,
                          item.isPrimary ? styles.linkPrimary : '',
                          isHistoryItem ? styles.linkHistory : '',
                          isActive ? styles.active : '',
                          pending ? styles.pending : '',
                        ]
                          .filter(Boolean)
                          .join(' ')
                      }
                    >
                      <span className={styles.linkRule} aria-hidden="true" />
                      <span className={styles.linkLabel}>{item.label}</span>
                      {isComplete && item.isPrimary && (
                        <span className={styles.completeDot} title="Results available" aria-label="Results available" />
                      )}
                      {active && (
                        <span className={styles.processingDot} title="Analysis running" aria-label="Analysis in progress" />
                      )}
                      {!active && !isComplete && isScanning && Boolean(item.needsResults) && !pending && (
                        <span className={styles.pendingDot} title="Awaiting this stage" aria-label="Awaiting this stage" />
                      )}
                      {pending && !isScanning && (
                        <span className={styles.pendingDot} title="Awaiting scan results" aria-label="Awaiting results" />
                      )}
                    </NavLink>
                  </li>
                );
              })}

            </ul>
          </div>
        ))}
      </div>

      <p className={styles.footer}>
        Enterprise Cryptographic
        <br />
        Discovery &amp; Analysis Tool
      </p>
    </nav>
  );
}
