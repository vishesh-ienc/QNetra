import { useEffect, useRef, type ReactNode } from 'react';
import styles from './Drawer.module.css';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  eyebrow?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: 'md' | 'lg';
}

/**
 * Right-hand investigation panel. Deep evidence lives here, not on the primary page.
 */
export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  eyebrow,
  children,
  footer,
  width = 'md',
}: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    panelRef.current?.focus();
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className={styles.root}>
      <button
        type="button"
        className={styles.scrim}
        onClick={onClose}
        aria-label="Close panel"
      />
      <div
        className={`${styles.panel} ${styles[width]}`}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : 'Detail panel'}
        ref={panelRef}
        tabIndex={-1}
      >
        <header className={styles.header}>
          <div className={styles.heading}>
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            <h2 className={styles.title}>{title}</h2>
            {subtitle && <div className={styles.subtitle}>{subtitle}</div>}
          </div>
          <button type="button" className={styles.close} onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className={styles.body}>{children}</div>
        {footer && <footer className={styles.footer}>{footer}</footer>}
      </div>
    </div>
  );
}

/* --- Building blocks used inside drawers ---------------------------------- */

export function DrawerSection({
  title,
  description,
  children,
  action,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className={styles.section}>
      <div className={styles.sectionHeader}>
        <h3 className={styles.sectionTitle}>{title}</h3>
        {action}
      </div>
      {description && <p className={styles.sectionDescription}>{description}</p>}
      {children}
    </section>
  );
}

export function KeyValue({
  items,
}: {
  items: { label: string; value: ReactNode; mono?: boolean }[];
}) {
  return (
    <dl className={styles.kv}>
      {items.map((item) => (
        <div className={styles.kvRow} key={item.label}>
          <dt className={styles.kvKey}>{item.label}</dt>
          <dd className={`${styles.kvValue} ${item.mono ? 'mono' : ''}`}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Prose({ children }: { children: ReactNode }) {
  return <p className={styles.prose}>{children}</p>;
}

export function StepList({ steps }: { steps: string[] }) {
  return (
    <ol className={styles.steps}>
      {steps.map((step, index) => (
        <li key={step}>
          <span className={`${styles.stepIndex} numeric`}>{index + 1}</span>
          <span>{step}</span>
        </li>
      ))}
    </ol>
  );
}

export function NoteList({ notes, tone = 'default' }: { notes: string[]; tone?: 'default' | 'quiet' }) {
  if (notes.length === 0) return null;
  return (
    <ul className={`${styles.notes} ${tone === 'quiet' ? styles.notesQuiet : ''}`}>
      {notes.map((note) => (
        <li key={note}>{note}</li>
      ))}
    </ul>
  );
}
