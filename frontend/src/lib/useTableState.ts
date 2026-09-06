import { useCallback, useEffect, useMemo, useState } from 'react';

export interface TableState {
  page: number;
  pageSize: number;
  sort: { key: string; order: 'asc' | 'desc' } | null;
  search: string;
  filters: Record<string, string>;
}

export interface TableStateApi extends TableState {
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
  toggleSort: (key: string) => void;
  setSearch: (value: string) => void;
  setFilter: (key: string, value: string) => void;
  resetFilters: () => void;
  activeFilterCount: number;
  /** Params in the shape the list endpoints accept. */
  queryParams: Record<string, string | number | undefined>;
}

/**
 * Table interaction state. Filtering, sorting, searching and pagination are
 * presentation concerns and are sent to the API as query parameters.
 */
export function useTableState(
  defaults: {
    sort?: { key: string; order: 'asc' | 'desc' };
    pageSize?: number;
  } = {},
): TableStateApi {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSizeState] = useState(defaults.pageSize ?? 50);
  const [sort, setSort] = useState(defaults.sort ?? null);
  const [search, setSearchState] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [filters, setFilters] = useState<Record<string, string>>({});

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 220);
    return () => clearTimeout(timer);
  }, [search]);

  // Every change to what is being listed returns to the first page. This happens
  // in the handler that caused it, so no render is invalidated after the fact.
  const setSearch = useCallback((value: string) => {
    setSearchState(value);
    setPage(1);
  }, []);

  const setPageSize = useCallback((size: number) => {
    setPageSizeState(size);
    setPage(1);
  }, []);

  const toggleSort = useCallback((key: string) => {
    setSort((current) => {
      if (current?.key !== key) return { key, order: 'desc' };
      return { key, order: current.order === 'desc' ? 'asc' : 'desc' };
    });
    setPage(1);
  }, []);

  const setFilter = useCallback((key: string, value: string) => {
    setFilters((current) => {
      const next = { ...current };
      if (!value) delete next[key];
      else next[key] = value;
      return next;
    });
    setPage(1);
  }, []);

  const resetFilters = useCallback(() => {
    setFilters({});
    setSearchState('');
    setPage(1);
  }, []);

  const activeFilterCount = Object.keys(filters).length + (debouncedSearch ? 1 : 0);

  const queryParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      ...(sort ? { sort: sort.key, order: sort.order } : {}),
      ...(debouncedSearch ? { q: debouncedSearch } : {}),
      ...filters,
    }),
    [page, pageSize, sort, debouncedSearch, filters],
  );

  return {
    page,
    pageSize,
    sort,
    search,
    filters,
    setPage,
    setPageSize,
    toggleSort,
    setSearch,
    setFilter,
    resetFilters,
    activeFilterCount,
    queryParams,
  };
}

/** Turns a backend count map into select options, largest first. */
export function facetOptions(
  counts: Record<string, number> | undefined,
  exclude: string[] = [],
): { value: string; label: string; count: number }[] {
  if (!counts) return [];
  return Object.entries(counts)
    .filter(([key, count]) => count > 0 && !exclude.includes(key))
    .sort((a, b) => b[1] - a[1])
    .map(([key, count]) => ({ value: key, label: key.replace(/_/g, ' '), count }));
}
