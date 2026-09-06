/**
 * Presentation-only formatting helpers.
 * Nothing here derives, scores, or classifies anything — see PROJECT_RULES RULE-004.
 */

export const NOT_AVAILABLE = '—';

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return NOT_AVAILABLE;
  return value.toLocaleString('en-US');
}

export function formatDecimal(value: number | null | undefined, places = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return NOT_AVAILABLE;
  return value.toFixed(places);
}

export function formatPercent(value: number | null | undefined, places = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return NOT_AVAILABLE;
  return `${(value * 100).toFixed(places)}%`;
}

export function formatYears(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return NOT_AVAILABLE;
  const rounded = Number.isInteger(value) ? value : Number(value.toFixed(1));
  return `${rounded} ${rounded === 1 ? 'year' : 'years'}`;
}

export function formatBits(value: number | null | undefined): string {
  if (value === null || value === undefined) return NOT_AVAILABLE;
  return `${value.toLocaleString('en-US')} bits`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return NOT_AVAILABLE;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return NOT_AVAILABLE;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return NOT_AVAILABLE;
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

/** Splits a path into a directory prefix and a file name for two-tone rendering. */
export function splitPath(filePath: string): { dir: string; file: string } {
  const index = filePath.lastIndexOf('/');
  if (index === -1) return { dir: '', file: filePath };
  return { dir: filePath.slice(0, index + 1), file: filePath.slice(index + 1) };
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

/** Collapses a multi-line snippet to a single readable line for table cells. */
export function oneLine(value: string | null | undefined, max = 90): string {
  if (!value) return NOT_AVAILABLE;
  const flattened = value.replace(/\s+/g, ' ').trim();
  return truncate(flattened, max);
}

/** Percentage of a whole, for bar widths only. Never a security figure. */
export function share(part: number, whole: number): number {
  if (!whole) return 0;
  return Math.max(0, Math.min(1, part / whole));
}
