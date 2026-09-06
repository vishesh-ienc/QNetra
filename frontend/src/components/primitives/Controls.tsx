import type { ReactNode } from 'react';
import styles from './Controls.module.css';

/* --- Filter bar ----------------------------------------------------------- */

export function FilterBar({
  children,
  trailing,
}: {
  children: ReactNode;
  trailing?: ReactNode;
}) {
  return (
    <div className={styles.filterBar}>
      <div className={styles.filters}>{children}</div>
      {trailing && <div className={styles.trailing}>{trailing}</div>}
    </div>
  );
}

/* --- Search --------------------------------------------------------------- */

export function SearchInput({
  value,
  onChange,
  placeholder = 'Search',
  width = '260px',
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  width?: string;
}) {
  return (
    <div className={styles.search} style={{ width }}>
      <span className={styles.searchGlyph} aria-hidden="true">
        ⌕
      </span>
      <input
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        className={styles.searchInput}
        aria-label={placeholder}
      />
      {value && (
        <button
          type="button"
          className={styles.clear}
          onClick={() => onChange('')}
          aria-label="Clear search"
        >
          ✕
        </button>
      )}
    </div>
  );
}

/* --- Select --------------------------------------------------------------- */

export interface SelectOption {
  value: string;
  label: string;
  count?: number;
}

export function Select({
  label,
  value,
  options,
  onChange,
  allLabel = 'All',
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  allLabel?: string;
}) {
  return (
    <label className={`${styles.select} ${value ? styles.selectActive : ''}`}>
      <span className={styles.selectLabel}>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{allLabel}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
            {option.count !== undefined ? ` (${option.count})` : ''}
          </option>
        ))}
      </select>
    </label>
  );
}

/* --- Segmented control ---------------------------------------------------- */

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: {
  value: T;
  options: { value: T; label: string; count?: number }[];
  onChange: (value: T) => void;
  ariaLabel: string;
}) {
  return (
    <div className={styles.segmented} role="tablist" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          className={`${styles.segment} ${value === option.value ? styles.segmentActive : ''}`}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {option.count !== undefined && (
            <span className={`${styles.segmentCount} numeric`}>{option.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

/* --- Buttons -------------------------------------------------------------- */

export function Button({
  children,
  onClick,
  variant = 'secondary',
  disabled,
  type = 'button',
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'ghost';
  disabled?: boolean;
  type?: 'button' | 'submit';
  title?: string;
}) {
  return (
    <button
      type={type}
      className={`${styles.button} ${styles[variant]}`}
      onClick={onClick}
      disabled={disabled}
      title={title}
    >
      {children}
    </button>
  );
}

/* --- Clear-filters affordance --------------------------------------------- */

export function ResetFilters({ onReset, count }: { onReset: () => void; count: number }) {
  if (count === 0) return null;
  return (
    <button type="button" className={styles.reset} onClick={onReset}>
      Clear {count} filter{count === 1 ? '' : 's'}
    </button>
  );
}
