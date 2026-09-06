import { createContext } from 'react';
import type { Scan } from '../api/types';

export interface ScanContextValue {
  scanId: string | null;
  setScanId: (id: string | null) => void;
  scan: Scan | null;
  scans: Scan[];
  isLoading: boolean;
  error: Error | null;
  /** True once the pipeline has produced analysable results. */
  hasResults: boolean;
  refetch: () => void;
}

export const ScanContext = createContext<ScanContextValue | null>(null);
