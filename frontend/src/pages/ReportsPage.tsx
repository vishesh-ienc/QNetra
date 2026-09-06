import { API_MODE } from '../api/client';
import { useCbom, useMosca, useRecommendations, useRisk } from '../api/queries';
import { formatDateTime, formatNumber } from '../lib/format';
import {
  Button,
  PageHeader,
  Section,
  SkeletonBlock,
  Unavailable,
} from '../components/primitives';
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
        lede="Everything QNetra concluded, in a form you can hand to someone else. Exports carry the engines' own output — the interface does not summarise, round or reinterpret the analysis on the way out."
        meta={<span>Scan completed {formatDateTime(scan.completed_at)}</span>}
      />

      <Section divided={false} eyebrow="Available now" title="Client-side exports">
        {!ready && <SkeletonBlock height={200} />}
        {ready && (
          <div className={styles.list}>
            <ExportRow
              name="CycloneDX 1.6 CBOM (JSON)"
              copy={`The full ${formatNumber(cbom.data?.components.length ?? 0)}-component cryptographic bill of materials exactly as core.cbom_generator serialised it.`}
              onDownload={() => download(cbom.data, `qnetra-cbom-${scanId}.json`)}
            />
            <ExportRow
              name="Risk assessment (JSON)"
              copy="Overall score, severity distribution, quantum exposure counts, and the per-asset assessment with its contributing factors."
              onDownload={() => download(risk.data, `qnetra-risk-${scanId}.json`)}
            />
            <ExportRow
              name="Mosca / HNDL assessment (JSON)"
              copy="The X, Y and Z terms per asset, the inequality outcome, urgency, HNDL exposure, and the assumptions the engine declared."
              onDownload={() => download(mosca.data, `qnetra-mosca-${scanId}.json`)}
            />
            <ExportRow
              name="PQC recommendations (JSON)"
              copy="Per-asset migration recommendations with rationale, guidance steps, assumptions and limitations."
              onDownload={() =>
                download(recommendations.data, `qnetra-recommendations-${scanId}.json`)
              }
            />
            <ExportRow
              name="Asset inventory (CSV)"
              copy="One row per asset with its classification, risk, urgency and recommended replacement — for spreadsheets and ticketing systems."
              onDownload={() =>
                downloadCsv(
                  buildInventoryCsv(
                    risk.data?.assessments ?? [],
                    mosca.data?.assessments ?? [],
                    recommendations.data?.recommendations ?? [],
                  ),
                  `qnetra-inventory-${scanId}.csv`,
                )
              }
            />
          </div>
        )}
      </Section>

      <Section
        eyebrow="Requires the API"
        title="Server-side exports"
        lede="These formats are produced by the backend from the same data. They are listed here because the contract defines them, not because they are simulated."
      >
        <div className={styles.list}>
          <Unavailable
            label="Executive report (PDF)"
            reason={
              <>
                Defined as <span className="mono">GET /scans/{'{id}'}/export?format=pdf</span>.
                {API_MODE === 'mock'
                  ? ' The QNetra API service is not running in this session.'
                  : ' This instance did not serve the endpoint.'}{' '}
                Generating a report in the browser would produce a document the engines never
                authored, so the interface does not do it.
              </>
            }
          />
          <Unavailable
            label="CycloneDX 1.6 CBOM (XML)"
            reason={
              <>
                Defined as{' '}
                <span className="mono">GET /scans/{'{id}'}/cbom/export?format=xml</span>, serialised
                by <span className="mono">core.cbom_generator</span>. The frontend will not
                re-serialise the JSON document into XML itself.
              </>
            }
          />
          <Unavailable
            label="Complete scan envelope (JSON)"
            reason={
              <>
                Defined as <span className="mono">GET /scans/{'{id}'}/export?format=json</span> —
                findings, assets, risk, CBOM and recommendations in one document assembled
                server-side. The individual exports above cover the same data from the endpoints
                that are reachable.
              </>
            }
          />
        </div>
      </Section>
    </>
  );
}

function ExportRow({
  name,
  copy,
  onDownload,
}: {
  name: string;
  copy: string;
  onDownload: () => void;
}) {
  return (
    <div className={styles.row}>
      <div className={styles.rowBody}>
        <p className={styles.rowName}>{name}</p>
        <p className={styles.rowCopy}>{copy}</p>
      </div>
      <Button onClick={onDownload}>Download</Button>
    </div>
  );
}

/* --- Download helpers ----------------------------------------------------- */

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function download(payload: unknown, filename: string): void {
  saveBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), filename);
}

function downloadCsv(csv: string, filename: string): void {
  saveBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), filename);
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * Flattens the engine outputs into one row per asset. Every column is a value an
 * engine produced; the export adds no derived column of its own.
 */
function buildInventoryCsv(
  risk: { asset_id: string; risk_score: number; severity: string; rationale: string }[],
  mosca: {
    asset_id: string;
    urgency: string;
    hndl_exposure: string;
    x_plus_y: number | null;
    z_quantum_arrival_years: number | null;
    exposure_gap_years: number | null;
  }[],
  recommendations: {
    asset_id: string;
    current_algorithm: string;
    current_primitive: string;
    recommendation_type: string;
    recommended_algorithm: string | null;
    pqc_standard: string | null;
    hybrid_recommendation: string | null;
    migration_complexity: string;
  }[],
): string {
  const moscaByAsset = new Map(mosca.map((entry) => [entry.asset_id, entry]));
  const riskByAsset = new Map(risk.map((entry) => [entry.asset_id, entry]));

  const header = [
    'asset_id',
    'algorithm',
    'primitive_type',
    'risk_score',
    'risk_severity',
    'risk_rationale',
    'mosca_urgency',
    'hndl_exposure',
    'x_plus_y_years',
    'z_years',
    'exposure_gap_years',
    'recommendation_type',
    'recommended_algorithm',
    'pqc_standard',
    'hybrid_scheme',
    'migration_complexity',
  ];

  const rows = recommendations.map((recommendation) => {
    const riskEntry = riskByAsset.get(recommendation.asset_id);
    const moscaEntry = moscaByAsset.get(recommendation.asset_id);
    return [
      recommendation.asset_id,
      recommendation.current_algorithm,
      recommendation.current_primitive,
      riskEntry?.risk_score,
      riskEntry?.severity,
      riskEntry?.rationale,
      moscaEntry?.urgency,
      moscaEntry?.hndl_exposure,
      moscaEntry?.x_plus_y,
      moscaEntry?.z_quantum_arrival_years,
      moscaEntry?.exposure_gap_years,
      recommendation.recommendation_type,
      recommendation.recommended_algorithm,
      recommendation.pqc_standard,
      recommendation.hybrid_recommendation,
      recommendation.migration_complexity,
    ].map(csvCell);
  });

  return [header.join(','), ...rows.map((row) => row.join(','))].join('\n');
}
