import { useState } from 'react';
import { api, type ExportedFile } from '../api/endpoints';
import { useCbom, useMosca, useRecommendations, useRisk } from '../api/queries';
import { formatDateTime, formatNumber } from '../lib/format';
import { Button, ErrorState, PageHeader, Section, SkeletonBlock } from '../components/primitives';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import styles from './ReportsPage.module.css';

export function ReportsPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const risk = useRisk(scanId);
  const mosca = useMosca(scanId);
  const recommendations = useRecommendations(scanId);
  const cbom = useCbom(scanId);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const ready = Boolean(risk.data && mosca.data && recommendations.data && cbom.data);

  return (
    <>
      <PageHeader
        eyebrow="Response"
        title="Reports"
        lede="Everything QNetra concluded, in a form you can hand to someone else. Every export carries the engines' own output — the interface does not summarise, round, or reinterpret the analysis on the way out."
        meta={<span>Scan completed {formatDateTime(scan.completed_at)}</span>}
      />

      <Section divided={false} eyebrow="From this session" title="Already fetched">
        <p className={styles.sectionNote}>
          These save the exact data already loaded from the API for this scan — no extra request.
        </p>
        {!ready && <SkeletonBlock height={160} />}
        {ready && (
          <div className={styles.list}>
            <ExportRow
              name="CycloneDX 1.6 CBOM (JSON)"
              copy={`The full ${formatNumber(cbom.data?.components.length ?? 0)}-component cryptographic bill of materials exactly as core.cbom_generator serialised it.`}
              onDownload={() =>
                saveJson(cbom.data, `qnetra-cbom-${scanId}.json`)
              }
            />
            <ExportRow
              name="Risk assessment (JSON)"
              copy="Overall score, severity distribution, quantum exposure counts, and the per-asset assessment with its contributing factors."
              onDownload={() => saveJson(risk.data, `qnetra-risk-${scanId}.json`)}
            />
            <ExportRow
              name="Mosca / HNDL assessment (JSON)"
              copy="The X, Y and Z terms per asset, the inequality outcome, urgency, HNDL exposure, and the assumptions the engine declared."
              onDownload={() => saveJson(mosca.data, `qnetra-mosca-${scanId}.json`)}
            />
            <ExportRow
              name="PQC recommendations (JSON)"
              copy="Per-asset migration recommendations with rationale, guidance steps, assumptions and limitations."
              onDownload={() =>
                saveJson(recommendations.data, `qnetra-recommendations-${scanId}.json`)
              }
            />
          </div>
        )}
      </Section>

      <Section
        eyebrow="Server-composed"
        title="Built fresh by the API"
        lede="These are assembled server-side from the same scan record — a different encoding (XML), a flattened spreadsheet (CSV), or every result bundled into one document. Requires the live backend."
      >
        <div className={styles.list}>
          <ExportRow
            name="CycloneDX 1.6 CBOM (XML)"
            copy="The identical inventory, serialised by core.cbom_generator's XML writer instead of JSON."
            onDownload={() => api.exportCbom(scanId, 'xml').then(saveExportedFile)}
          />
          <ExportRow
            name="Asset inventory (CSV)"
            copy="One row per asset — classification, risk, Mosca urgency and the recommended replacement — for spreadsheets and ticketing systems."
            onDownload={() => api.exportScan(scanId, 'csv').then(saveExportedFile)}
          />
          <ExportRow
            name="Complete scan envelope (JSON)"
            copy="Findings, assets, risk, Mosca, recommendations and CBOM in one document, assembled server-side."
            onDownload={() => api.exportScan(scanId, 'json').then(saveExportedFile)}
          />
          <ExportRow
            name="Executive report (PDF)"
            copy="No engine in core/ produces report prose or page layout, so this is declined by the API rather than generated client-side."
            onDownload={() => api.exportScan(scanId, 'pdf').then(saveExportedFile)}
          />
        </div>
      </Section>
    </>
  );
}

/* --- Export row: owns its own attempt/loading/error state -------------------
   Every row follows the same shape (call an async producer, save the result,
   or show why it failed) so failures — including the PDF route's honest
   NOT_IMPLEMENTED — surface as real errors, not a static disclaimer. */

function ExportRow({
  name,
  copy,
  onDownload,
}: {
  name: string;
  copy: string;
  onDownload: () => Promise<void>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const handleClick = async () => {
    setPending(true);
    setError(null);
    try {
      await onDownload();
    } catch (caught) {
      setError(caught);
    } finally {
      setPending(false);
    }
  };

  return (
    <div className={styles.row}>
      <div className={styles.rowMain}>
        <div className={styles.rowBody}>
          <p className={styles.rowName}>{name}</p>
          <p className={styles.rowCopy}>{copy}</p>
        </div>
        <Button onClick={handleClick} disabled={pending}>
          {pending ? 'Preparing…' : 'Download'}
        </Button>
      </div>
      {error !== null && <ErrorState error={error} compact />}
    </div>
  );
}

/* --- Save helpers ----------------------------------------------------------- */

function saveBlob(content: string, filename: string, mediaType: string): void {
  const blob = new Blob([content], { type: mediaType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function saveJson(payload: unknown, filename: string): Promise<void> {
  saveBlob(JSON.stringify(payload, null, 2), filename, 'application/json');
}

function saveExportedFile(file: ExportedFile): void {
  saveBlob(file.content, file.filename, file.mediaType);
}
