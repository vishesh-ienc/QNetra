import { Link } from 'react-router-dom';
import { API_MODE } from '../../api/client';
import { useScanContext } from '../../state/useScanContext';
import { EmptyState, ErrorState, PageHeader, SkeletonBlock } from '../../components/primitives';

/**
 * Distinguishes the states the product must never conflate:
 * loading, no scan at all, a scan still running, and a failed scan.
 */
export function NoScanState({ scanRunning = false }: { scanRunning?: boolean }) {
  const { scan, isLoading, error, refetch } = useScanContext();

  if (isLoading) {
    return (
      <>
        <PageHeader eyebrow="QNetra" title="Loading" lede="Reading scan state from the API." />
        <SkeletonBlock height={280} />
      </>
    );
  }

  const is404 = (error as unknown as { status?: number; code?: string })?.status === 404 ||
    (error as unknown as { status?: number; code?: string })?.code === 'SCAN_NOT_FOUND';

  if (error && !is404) {
    return (
      <>
        <PageHeader
          eyebrow="QNetra"
          title="Unavailable"
          lede="The application could not reach the analysis API."
        />
        <ErrorState error={error} onRetry={refetch} />
      </>
    );
  }

  if (scanRunning && scan) {
    const failed = scan.status === 'FAILED' || scan.status === 'CANCELLED';
    return (
      <>
        <PageHeader
          eyebrow="Scan"
          title={failed ? 'This scan did not complete' : 'Analysis in progress'}
          lede={
            failed
              ? 'Results are not available because the pipeline did not finish. The scan view lists what the run recorded before it stopped.'
              : 'The pipeline is still running. This view will populate as soon as the analysis stages complete.'
          }
        />
        <EmptyState
          title={failed ? `Scan status: ${scan.status}` : `Currently at: ${scan.current_stage ?? 'queued'}`}
          description={
            failed
              ? scan.errors.length > 0
                ? scan.errors.slice(0, 3).join(' · ')
                : 'Open the scan view for the recorded errors and warnings.'
              : 'Analysis results become available once the pipeline reaches COMPLETED. Nothing is estimated in the meantime.'
          }
          action={<Link to="/scan">View scan pipeline →</Link>}
        />
      </>
    );
  }


  return (
    <>
      <PageHeader
        eyebrow="QNetra"
        title="No scan selected"
        lede="QNetra analyses a target and turns what it finds into a cryptographic inventory, a risk assessment, and a migration plan. Start by running a scan."
      />
      <EmptyState
        title="You haven't started a scan yet"
        description={
          API_MODE === 'mock'
            ? 'The QNetra API service is not running, so no scans could be listed.'
            : 'No scans have been run for this instance yet. Upload an artifact or provide a repository to begin discovery.'
        }
        action={<Link to="/scan">Start a scan →</Link>}
      />
    </>
  );
}

