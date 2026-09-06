import { NavLink } from 'react-router-dom';
import { useScanContext } from '../../state/useScanContext';
import { NAV } from './nav';
import styles from './SideNav.module.css';

export function SideNav({ onNavigate }: { onNavigate?: () => void }) {
  const { hasResults } = useScanContext();

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
          <span className={styles.brandSub}>Cryptographic Discovery</span>
        </span>
      </NavLink>

      <div className={styles.groups}>
        {NAV.map((group) => (
          <div className={styles.group} key={group.label}>
            <p className={styles.groupLabel}>{group.label}</p>
            <ul>
              {group.items.map((item) => {
                const pending = Boolean(item.needsResults) && !hasResults;
                return (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.to === '/'}
                      title={item.question}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        `${styles.link} ${isActive ? styles.active : ''} ${
                          pending ? styles.pending : ''
                        }`
                      }
                    >
                      <span className={styles.linkRule} aria-hidden="true" />
                      {item.label}
                      {pending && (
                        <span className={styles.pendingDot} title="Awaiting scan results" />
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
