import { useEffect, useRef, useState } from 'react';
import styles from './SectionNav.module.css';

export interface SectionNavItem {
  id: string;
  label: string;
}

/**
 * Sticky in-page anchor bar for a long, single-page result. Scrolls smoothly
 * to each section and tracks which one is currently in view — the reader can
 * jump to Migration or Evidence directly instead of scrolling past everything
 * between here and there.
 */
export function SectionNav({ items }: { items: SectionNavItem[] }) {
  const [active, setActive] = useState(items[0]?.id ?? '');
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    const elements = items
      .map((item) => document.getElementById(item.id))
      .filter((el): el is HTMLElement => el !== null);
    if (elements.length === 0) return undefined;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length > 0) setActive(visible[0].target.id);
      },
      { rootMargin: '-15% 0px -70% 0px', threshold: [0, 1] },
    );
    elements.forEach((el) => observer.observe(el));
    observerRef.current = observer;
    return () => observer.disconnect();
  }, [items]);

  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (!el) return;
    const top = el.getBoundingClientRect().top + window.scrollY - 72;
    window.scrollTo({ top, behavior: 'smooth' });
  };

  return (
    <nav className={styles.nav} aria-label="Scan result sections">
      <div className={styles.scroll}>
        {items.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`${styles.link} ${active === item.id ? styles.active : ''}`}
            onClick={() => scrollTo(item.id)}
            aria-current={active === item.id ? 'true' : undefined}
          >
            {item.label}
          </button>
        ))}
      </div>
    </nav>
  );
}
