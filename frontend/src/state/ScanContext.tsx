import { useCallback, useMemo, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/endpoints';
import { queryKeys } from '../api/queries';
import { ScanContext, type ScanContextValue } from './scanContext';

const STORAGE_KEY = 'qnetra.active-scan-id';

const readStored = (): string | null => {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
};

export function ScanProvider({ children }: { children: ReactNode }) {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(readStored);

  const scansQuery = useQuery({
    queryKey: queryKeys.scans,
    queryFn: () => api.listScans(),
  });

  const scans = useMemo(() => scansQuery.data?.data ?? [], [scansQuery.data]);

  // Fall back to the most recent scan when nothing is selected, or when the id
  // held in storage refers to a scan this instance no longer knows about.
  const scanId = useMemo(() => {
    if (selectedScanId && scans.some((entry) => entry.scan_id === selectedScanId)) {
      return selectedScanId;
    }
    return scans[0]?.scan_id ?? null;
  }, [selectedScanId, scans]);

  const setScanId = useCallback((id: string | null) => {
    setSelectedScanId(id);
    try {
      if (id) window.localStorage.setItem(STORAGE_KEY, id);
      else window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* storage unavailable — selection stays in memory for this session */
    }
  }, []);

  const scanQuery = useQuery({
    queryKey: queryKeys.scan(scanId ?? ''),
    queryFn: () => api.getScan(scanId as string),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'RUNNING' || status === 'QUEUED' ? 3000 : false;
    },
  });

  const scan = scanQuery.data ?? null;

  const value = useMemo<ScanContextValue>(
    () => ({
      scanId,
      setScanId,
      scan,
      scans,
      isLoading: scansQuery.isLoading || scanQuery.isLoading,
      error: (scansQuery.error as Error | null) ?? (scanQuery.error as Error | null),
      hasResults:
        scan !== null && (scan.status === 'COMPLETED' || scan.status === 'PARTIAL'),
      refetch: () => {
        void scansQuery.refetch();
        void scanQuery.refetch();
      },
    }),
    [scanId, setScanId, scan, scans, scansQuery, scanQuery],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}
