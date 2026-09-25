import { useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { scanDisplayName } from '../../lib/format';
import { useScanContext } from '../../state/useScanContext';
import type { PipelineStage, Scan } from '../../api/types';
import { NAV } from './nav';
import styles from './SideNav.module.css';

export function SideNav({ onNavigate }: { onNavigate?: () => void }) {
  const { hasResults, scan, scans, scanId, setScanId } = useScanContext();
  const navigate = useNavigate();
  const location = useLocation();
  const [isHistoryOpen, setIsHistoryOpen] = useState(true);

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

  function handleSelectScan(selectedScan: Scan) {
    setScanId(selectedScan.scan_id);
    if (selectedScan.status === 'RUNNING' || selectedScan.status === 'QUEUED') {
      navigate('/scan');
    } else if (location.pathname === '/history' || location.pathname === '/scan' || location.pathname === '/') {
      navigate('/posture');
    }
    onNavigate?.();
  }

  return (
    <nav className={styles.nav} aria-label="Primary">
      <NavLink to={hasResults ? '/posture' : '/'} className={styles.brand} onClick={onNavigate}>
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

                if (isHistoryItem) {
                  return (
                    <li key={item.to} className={styles.historyNavItemContainer}>
                      <div className={styles.historyNavRow}>
                        <NavLink
                          to={item.to}
                          title={item.question}
                          onClick={() => {
                            setIsHistoryOpen(true);
                            onNavigate?.();
                          }}
                          className={({ isActive }) =>
                            [
                              styles.link,
                              styles.linkHistory,
                              isActive ? styles.active : '',
                            ]
                              .filter(Boolean)
                              .join(' ')
                          }
                        >
                          <span className={styles.linkRule} aria-hidden="true" />
                          <span className={styles.linkLabel}>{item.label}</span>
                          {scans.length > 0 && (
                            <span className={styles.historyCountBadge}>{scans.length}</span>
                          )}
                        </NavLink>
                        <button
                          type="button"
                          className={`${styles.historyChevronBtn} ${isHistoryOpen ? styles.historyChevronExpanded : ''}`}
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setIsHistoryOpen((prev) => !prev);
                          }}
                          aria-label={isHistoryOpen ? 'Collapse scan history' : 'Expand scan history'}
                          title={isHistoryOpen ? 'Collapse previous scans' : 'Expand previous scans'}
                        >
                          <svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">
                            <path d="M4.646 6.646a.5.5 0 0 1 .708 0L8 9.293l2.646-2.647a.5.5 0 0 1 .708.708l-3 3a.5.5 0 0 1-.708 0l-3-3a.5.5 0 0 1 0-.708z" />
                          </svg>
                        </button>
                      </div>

                      {isHistoryOpen && (
                        <div className={styles.historyDrawer}>
                          <div className={styles.historyDrawerHeader}>
                            <span className={styles.historyDrawerHeading}>Previous Scans</span>
                            {scans.length > 0 && (
                              <span className={styles.historyDrawerSubtext}>{scans.length} total</span>
                            )}
                          </div>

                          {scans.length === 0 ? (
                            <div className={styles.historyEmptyState}>
                              <span className={styles.historyEmptyText}>No previous scans</span>
                              <NavLink
                                to="/scan"
                                className={styles.historyNewScanBtn}
                                onClick={onNavigate}
                              >
                                + Start a scan
                              </NavLink>
                            </div>
                          ) : (
                            <ul className={styles.historyScansList}>
                              {scans.map((s) => {
                                const isSelected = s.scan_id === scanId;
                                const isScanRunning = s.status === 'RUNNING' || s.status === 'QUEUED';
                                const isScanCompleted = s.status === 'COMPLETED';
                                const isScanFailed = s.status === 'FAILED' || s.status === 'CANCELLED';
                                const isScanPartial = s.status === 'PARTIAL';
                                const displayName = scanDisplayName(s);

                                let dotClass = styles.dotDefault;
                                if (isScanCompleted) dotClass = styles.dotCompleted;
                                else if (isScanRunning) dotClass = styles.dotRunning;
                                else if (isScanFailed) dotClass = styles.dotFailed;
                                else if (isScanPartial) dotClass = styles.dotPartial;

                                return (
                                  <li key={s.scan_id}>
                                    <button
                                      type="button"
                                      className={`${styles.scanItemBtn} ${isSelected ? styles.scanItemBtnActive : ''}`}
                                      onClick={() => handleSelectScan(s)}
                                      title={`${displayName} (${s.status})`}
                                    >
                                      <span
                                        className={`${styles.scanStatusDot} ${dotClass}`}
                                        aria-hidden="true"
                                      />
                                      <span className={styles.scanItemTitle}>{displayName}</span>
                                      {isSelected && (
                                        <span className={styles.scanItemActiveBadge}>Active</span>
                                      )}
                                    </button>
                                  </li>
                                );
                              })}
                            </ul>
                          )}
                        </div>
                      )}
                    </li>
                  );
                }

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

