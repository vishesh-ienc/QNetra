import { useContext } from 'react';
import { ScanContext, type ScanContextValue } from './scanContext';

/** Access the active scan. Throws outside <ScanProvider> rather than returning a null scan. */
export function useScanContext(): ScanContextValue {
  const context = useContext(ScanContext);
  if (!context) throw new Error('useScanContext must be used inside <ScanProvider>.');
  return context;
}
