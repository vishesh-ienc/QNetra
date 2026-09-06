import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { SideNav } from './SideNav';
import { TopBar } from './TopBar';
import styles from './AppShell.module.css';

export function AppShell() {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

  // A new view starts at the top; the nav closes from its own links and the scrim.
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
  }, [location.pathname]);

  return (
    <div className={styles.shell}>
      <aside className={`${styles.aside} ${navOpen ? styles.asideOpen : ''}`}>
        <SideNav onNavigate={() => setNavOpen(false)} />
      </aside>
      {navOpen && (
        <button
          type="button"
          className={styles.navScrim}
          onClick={() => setNavOpen(false)}
          aria-label="Close navigation"
        />
      )}
      <div className={styles.main}>
        <TopBar onOpenNav={() => setNavOpen(true)} />
        <main className={styles.content}>
          <div className={styles.container}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
