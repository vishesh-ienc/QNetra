import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '../api/client';
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
  const queryClient = useQueryClient();
  const [selectedScanId, setSelectedScanId] = useState<string | null>(readStored);

  const scansQuery = useQuery({
    queryKey: queryKeys.scans,
    queryFn: () => api.listScans(),
    // Only poll when a scan is selected so the list stays fresh during active scans.
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      // Check if any scan in the list is currently running.
      const anyRunning = (data as { data?: { status: string }[] }).data?.some(
        (s) => s.status === 'RUNNING' || s.status === 'QUEUED',
      );
      return anyRunning ? 5000 : false;
    },
  });

  const scans = useMemo(() => scansQuery.data?.data ?? [], [scansQuery.data]);

  // Determine active scanId:
  // - If scans query finished and there are NO scans, scanId MUST be null.
  // - If selectedScanId matches a known scan, use it.
  // - If scans query finished and selectedScanId is NOT in scans, fall back to the newest scan.
  // - Only while scans query is in flight do we temporarily use selectedScanId.
  const scanId = useMemo(() => {
    if (selectedScanId) return selectedScanId;
    if (scansQuery.isSuccess) {
      return scans[0]?.scan_id ?? null;
    }
    return null;
  }, [selectedScanId, scans, scansQuery.isSuccess]);

  const setScanId = useCallback(
    (id: string | null) => {
      setSelectedScanId(id);
      try {
        if (id) window.localStorage.setItem(STORAGE_KEY, id);
        else window.localStorage.removeItem(STORAGE_KEY);
      } catch {
        /* storage unavailable — selection stays in memory for this session */
      }
      // Invalidate the scans list so it refetches and includes the new scan.
      void queryClient.invalidateQueries({ queryKey: queryKeys.scans });
    },
    [queryClient],
  );

  // Keep localStorage aligned with valid scan state
  useEffect(() => {
    if (scansQuery.isSuccess) {
      if (scans.length === 0) {
        try {
          window.localStorage.removeItem(STORAGE_KEY);
        } catch {
          /* storage unavailable */
        }
      } else if (scanId) {
        try {
          window.localStorage.setItem(STORAGE_KEY, scanId);
        } catch {
          /* storage unavailable */
        }
      }
    }
  }, [scansQuery.isSuccess, scans.length, scanId]);

  const scanQuery = useQuery({
    queryKey: queryKeys.scan(scanId ?? ''),
    queryFn: () => api.getScan(scanId as string),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'RUNNING' || status === 'QUEUED' ? 3000 : false;
    },
  });

  // If fetching the selected scan 404s (e.g. backend restarted), clean up storage
  useEffect(() => {
    if (scanQuery.isError) {
      const err = scanQuery.error as unknown as ApiError;
      if (err?.status === 404 || err?.code === 'SCAN_NOT_FOUND') {
        setSelectedScanId(null);
        try {
          window.localStorage.removeItem(STORAGE_KEY);
        } catch {
          /* storage unavailable */
        }
      }
    }
  }, [scanQuery.isError, scanQuery.error]);

  const scan = scanQuery.data ?? null;

  // 404 on a specific scan is not an API connectivity failure; it just means no such scan exists.
  const isScanNotFound =
    (scanQuery.error as unknown as ApiError)?.status === 404 ||
    (scanQuery.error as unknown as ApiError)?.code === 'SCAN_NOT_FOUND';

  const effectiveError =
    (scansQuery.error as Error | null) ??
    (isScanNotFound ? null : (scanQuery.error as Error | null));

  const value = useMemo<ScanContextValue>(
    () => ({
      scanId,
      setScanId,
      scan,
      scans,
      isLoading: scansQuery.isLoading || (Boolean(scanId) && scanQuery.isLoading),
      error: effectiveError,
      hasResults:
        scan !== null && (scan.status === 'COMPLETED' || scan.status === 'PARTIAL'),
      refetch: () => {
        void scansQuery.refetch();
        void scanQuery.refetch();
      },
    }),
    [scanId, setScanId, scan, scans, scansQuery, scanQuery, effectiveError],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

