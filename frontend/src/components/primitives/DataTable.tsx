import type { ReactNode } from 'react';
import styles from './DataTable.module.css';

export interface Column<T> {
  key: string;
  header: string;
  /** Column is sortable server-side under this API sort key. */
  sortKey?: string;
  align?: 'left' | 'right';
  width?: string;
  /** Hidden below this breakpoint so narrow screens stay readable. */
  priority?: 'always' | 'lg' | 'xl';
  render: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  activeRowKey?: string | null;
  sort?: { key: string; order: 'asc' | 'desc' } | null;
  onSortChange?: (key: string) => void;
  emptyState?: ReactNode;
  caption?: string;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  activeRowKey,
  sort,
  onSortChange,
  emptyState,
  caption,
}: DataTableProps<T>) {
  if (rows.length === 0 && emptyState) {
    return <div className={styles.emptyWrap}>{emptyState}</div>;
  }

  return (
    <div className={styles.scroll}>
      <table className={styles.table}>
        {caption && <caption className="visually-hidden">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((column) => {
              const sortable = Boolean(column.sortKey && onSortChange);
              const isSorted = sort?.key === column.sortKey;
              return (
                <th
                  key={column.key}
                  scope="col"
                  style={{ width: column.width, textAlign: column.align ?? 'left' }}
                  data-priority={column.priority ?? 'always'}
                  aria-sort={
                    isSorted ? (sort?.order === 'asc' ? 'ascending' : 'descending') : undefined
                  }
                >
                  {sortable ? (
                    <button
                      type="button"
                      className={`${styles.sortButton} ${isSorted ? styles.sorted : ''}`}
                      onClick={() => onSortChange?.(column.sortKey as string)}
                    >
                      {column.header}
                      <span className={styles.sortGlyph} aria-hidden="true">
                        {isSorted ? (sort?.order === 'asc' ? '↑' : '↓') : '↕'}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
            {onRowClick && <th scope="col" className={styles.chevronCol} />}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            const active = activeRowKey === key;
            return (
              <tr
                key={key}
                className={`${onRowClick ? styles.clickable : ''} ${active ? styles.active : ''}`}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                role={onRowClick ? 'button' : undefined}
                onKeyDown={
                  onRowClick
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          onRowClick(row);
                        }
                      }
                    : undefined
                }
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    style={{ textAlign: column.align ?? 'left' }}
                    data-priority={column.priority ?? 'always'}
                  >
                    {column.render(row)}
                  </td>
                ))}
                {onRowClick && (
                  <td className={styles.chevronCol} aria-hidden="true">
                    <span className={styles.chevron}>›</span>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* --- Pagination ----------------------------------------------------------- */

interface PaginationBarProps {
  page: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  noun?: string;
}

export function PaginationBar({
  page,
  pageSize,
  totalItems,
  totalPages,
  onPageChange,
  onPageSizeChange,
  noun = 'rows',
}: PaginationBarProps) {
  if (totalItems === 0) return null;
  const first = (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, totalItems);

  return (
    <div className={styles.pagination}>
      <p className={styles.paginationCount}>
        <span className="numeric">
          {first.toLocaleString()}–{last.toLocaleString()}
        </span>{' '}
        of <span className="numeric">{totalItems.toLocaleString()}</span> {noun}
      </p>
      <div className={styles.paginationControls}>
        {onPageSizeChange && (
          <label className={styles.pageSize}>
            <span className="visually-hidden">Rows per page</span>
            <select
              value={pageSize}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
            >
              {[25, 50, 100, 200].map((size) => (
                <option key={size} value={size}>
                  {size} per page
                </option>
              ))}
            </select>
          </label>
        )}
        <button
          type="button"
          className={styles.pageButton}
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
        >
          Previous
        </button>
        <span className={`${styles.pageIndicator} numeric`}>
          {page} / {totalPages}
        </span>
        <button
          type="button"
          className={styles.pageButton}
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );
}
