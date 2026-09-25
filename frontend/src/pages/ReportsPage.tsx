import { useState } from 'react';
import { api, type ExportedFile } from '../api/endpoints';
import { useRisk } from '../api/queries';
import { formatDateTime, formatNumber } from '../lib/format';
import { Badge, Button, ErrorState, PageHeader, Section } from '../components/primitives';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import { ScanGate } from './shared/ScanGate';
import styles from './ReportsPage.module.css';

interface ExportAction {
  label: string;
  onDownload: () => Promise<ExportedFile>;
  primary?: boolean;
}

export function ReportsPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const risk = useRisk(scanId);

  // Custom export state
  const [customSections, setCustomSections] = useState<string[]>([
    'assets',
    'risk',
    'quantum',
    'migration',
    'cbom',
  ]);
  const [customFormat, setCustomFormat] = useState<'pdf' | 'json' | 'csv'>('pdf');
  const [customPending, setCustomPending] = useState(false);
  const [customError, setCustomError] = useState<unknown>(null);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) {
    return <ScanGate requiredStage="COMPLETED" pageName="Reports & Exports"><></></ScanGate>;
  }

  const targetName = scan.target?.name || scan.name || 'Scan Target';
  const totalAssets = scan.progress?.assets_count ?? 0;
  const overallSeverity = (scan.overall_severity || risk.data?.overall_severity || 'LOW') as any;
  const riskScore =
    scan.overall_risk_score !== null && scan.overall_risk_score !== undefined
      ? Number(scan.overall_risk_score).toFixed(1)
      : risk.data?.overall_risk_score !== undefined
        ? Number(risk.data.overall_risk_score).toFixed(1)
        : '—';
  const shorExposed = risk.data?.shor_vulnerable_count ?? '—';

  const toggleSection = (id: string) => {
    setCustomSections((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    );
  };

  const isCsvCompatible =
    customFormat !== 'csv' ||
    customSections.some((s) => ['assets', 'findings', 'migration'].includes(s));

  const handleCustomExport = async () => {
    if (!scanId || customSections.length === 0 || !isCsvCompatible) return;
    setCustomPending(true);
    setCustomError(null);
    try {
      const file = await api.exportCustomReport(scanId, {
        sections: customSections,
        format: customFormat,
      });
      downloadFile(file);
    } catch (err) {
      setCustomError(err);
    } finally {
      setCustomPending(false);
    }
  };

  return (
    <ScanGate requiredStage="COMPLETED" pageName="Reports & Exports">
      <>
        <PageHeader
          eyebrow="Export Center"
          title="Reports &amp; Exports"
          lede="Download high-assurance cryptographic assessment reports, machine-readable CBOM inventories, remediation roadmaps, and custom data selections."
        />

        {/* Current Scan Banner */}
        <div className={styles.banner}>
          <div className={styles.bannerMain}>
            <div className={styles.bannerTarget}>
              <span>{targetName}</span>
              <Badge tone={overallSeverity} size="sm" variant="quiet">
                {overallSeverity} Risk
              </Badge>
            </div>
            <div className={styles.bannerMeta}>
              <span>Scan completed {formatDateTime(scan.completed_at)}</span>
              <span>·</span>
              <span>{formatNumber(totalAssets)} crypto assets identified</span>
            </div>
          </div>
          <div className={styles.bannerStats}>
            <div className={styles.bannerStatItem}>
              <span className={styles.bannerStatVal}>{riskScore}</span>
              <span className={styles.bannerStatLabel}>Risk Score</span>
            </div>
            <div className={styles.bannerStatItem}>
              <span className={styles.bannerStatVal}>{shorExposed}</span>
              <span className={styles.bannerStatLabel}>Shor Exposed</span>
            </div>
          </div>
        </div>

        {/* RECOMMENDED REPORTS */}
        <Section
              divided={false}
              eyebrow="Leadership & Remediation"
              title="Recommended Reports"
              lede="Curated documents designed for engineering managers, CISOs, security leaders, and migration architects."
            >
              <div className={styles.list}>
                <ExportCard
                  title="Executive Cryptographic Assessment"
                  description="A concise assessment summarizing organizational cryptographic posture, Shor/Grover quantum exposure, and highest-priority migration actions."
                  actions={[
                    {
                      label: 'PDF',
                      primary: true,
                      onDownload: () => api.exportExecutiveReport(scanId),
                    },
                  ]}
                />

                <ExportCard
                  title="PQC Migration Plan"
                  description="Prioritized cryptographic migration actions, replacement algorithms (NIST FIPS 203/204/205), hybrid schemes, and urgency timelines."
                  actions={[
                    {
                      label: 'PDF',
                      onDownload: () => api.exportMigrationReport(scanId, 'pdf'),
                    },
                    {
                      label: 'CSV',
                      onDownload: () => api.exportMigrationReport(scanId, 'csv'),
                    },
                    {
                      label: 'JSON',
                      onDownload: () => api.exportMigrationReport(scanId, 'json'),
                    },
                  ]}
                />
              </div>
            </Section>

            {/* DATA EXPORTS */}
            <Section
              eyebrow="Machine-Readable Catalogs"
              title="Data Exports"
              lede="Complete structured datasets for security tooling, pipelines, spreadsheets, and technical deep-dives."
            >
              <div className={styles.list}>
                <ExportCard
                  title="Cryptographic Bill of Materials (CBOM)"
                  description="Machine-readable inventory of cryptographic assets, algorithms, key sizes, curves, and libraries conforming strictly to CycloneDX 1.6."
                  actions={[
                    {
                      label: 'JSON',
                      onDownload: () => api.exportCbom(scanId, 'json'),
                    },
                    {
                      label: 'XML',
                      onDownload: () => api.exportCbom(scanId, 'xml'),
                    },
                  ]}
                />

                <ExportCard
                  title="Crypto Assets"
                  description="Normalized cryptographic assets with algorithm parameters, classification, quantum exposure, Mosca urgency, and location references."
                  actions={[
                    {
                      label: 'CSV',
                      onDownload: () => api.exportCryptoAssets(scanId, 'csv'),
                    },
                    {
                      label: 'JSON',
                      onDownload: () => api.exportCryptoAssets(scanId, 'json'),
                    },
                  ]}
                />

                <ExportCard
                  title="Evidence & Findings"
                  description="Raw scanner discoveries, detection methods, confidence ratings, and exact source file locations behind QNetra's conclusions."
                  actions={[
                    {
                      label: 'CSV',
                      onDownload: () => api.exportEvidenceFindings(scanId, 'csv'),
                    },
                    {
                      label: 'JSON',
                      onDownload: () => api.exportEvidenceFindings(scanId, 'json'),
                    },
                  ]}
                />
              </div>
            </Section>

            {/* COMPLETE TECHNICAL ASSESSMENT */}
            <Section
              eyebrow="Full Documentation"
              title="Complete Assessment"
              lede="Exhaustive assessment artifact suitable for formal audits, compliance packages, and full technical reviews."
            >
              <div className={styles.list}>
                <ExportCard
                  title="Complete Technical Report"
                  description="Full cryptographic assessment covering metadata, posture, normalized assets catalog, raw findings, quantum exposure, Mosca calculations, migration recommendations, and CBOM summary."
                  actions={[
                    {
                      label: 'Generate PDF',
                      primary: true,
                      onDownload: () => api.exportTechnicalReport(scanId),
                    },
                  ]}
                />
              </div>
            </Section>

            {/* CUSTOM EXPORT CENTER */}
            <Section
              eyebrow="Selective Tailoring"
              title="Custom Export"
              lede="Select specific assessment domains and your preferred file format to receive a tailored export."
            >
              <div className={styles.customPanel}>
                <div className={styles.customGrid}>
                  <CheckboxItem
                    id="assets"
                    label="Crypto Assets"
                    checked={customSections.includes('assets')}
                    onChange={() => toggleSection('assets')}
                  />
                  <CheckboxItem
                    id="findings"
                    label="Evidence & Findings"
                    checked={customSections.includes('findings')}
                    onChange={() => toggleSection('findings')}
                  />
                  <CheckboxItem
                    id="risk"
                    label="Risk Analysis"
                    checked={customSections.includes('risk')}
                    onChange={() => toggleSection('risk')}
                  />
                  <CheckboxItem
                    id="quantum"
                    label="Quantum Exposure"
                    checked={customSections.includes('quantum')}
                    onChange={() => toggleSection('quantum')}
                  />
                  <CheckboxItem
                    id="mosca"
                    label="Mosca / HNDL"
                    checked={customSections.includes('mosca')}
                    onChange={() => toggleSection('mosca')}
                  />
                  <CheckboxItem
                    id="migration"
                    label="PQC Migration Plan"
                    checked={customSections.includes('migration')}
                    onChange={() => toggleSection('migration')}
                  />
                  <CheckboxItem
                    id="cbom"
                    label="CBOM (CycloneDX)"
                    checked={customSections.includes('cbom')}
                    onChange={() => toggleSection('cbom')}
                  />
                </div>

                <div className={styles.formatRow}>
                  <div className={styles.formatChooser}>
                    <span className={styles.formatLabel}>Format:</span>
                    <div className={styles.formatPills}>
                      {(['pdf', 'json', 'csv'] as const).map((fmt) => (
                        <button
                          key={fmt}
                          type="button"
                          className={`${styles.formatPill} ${customFormat === fmt ? styles.formatPillActive : ''}`}
                          onClick={() => setCustomFormat(fmt)}
                        >
                          {fmt.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>

                  <Button
                    variant="primary"
                    disabled={customPending || customSections.length === 0 || !isCsvCompatible}
                    onClick={handleCustomExport}
                  >
                    {customPending ? 'Generating Export…' : 'Generate Export'}
                  </Button>
                </div>

                {customFormat === 'csv' && !isCsvCompatible && (
                  <p className={`${styles.formatAdvice} ${styles.formatWarning}`}>
                    CSV export requires tabular data (Crypto Assets, Evidence &amp; Findings, or Migration Plan). For CBOM, use CycloneDX JSON or XML.
                  </p>
                )}

                {customError !== null && <ErrorState error={customError} compact />}
              </div>
            </Section>
          </>
        </ScanGate>
  );
}

/* --- Export Card Component ------------------------------------------------ */

function ExportCard({
  title,
  description,
  actions,
}: {
  title: string;
  description: string;
  actions: ExportAction[];
}) {
  const [pendingLabel, setPendingLabel] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const handleDownload = async (action: ExportAction) => {
    setPendingLabel(action.label);
    setError(null);
    try {
      const file = await action.onDownload();
      downloadFile(file);
    } catch (caught) {
      setError(caught);
    } finally {
      setPendingLabel(null);
    }
  };

  return (
    <div className={styles.exportCard}>
      <div className={styles.cardTop}>
        <div className={styles.cardBody}>
          <div className={styles.cardTitle}>{title}</div>
          <div className={styles.cardDesc}>{description}</div>
        </div>
        <div className={styles.buttonGroup}>
          {actions.map((act) => {
            const isPending = pendingLabel === act.label;
            return (
              <Button
                key={act.label}
                variant={act.primary ? 'primary' : 'secondary'}
                disabled={pendingLabel !== null}
                onClick={() => handleDownload(act)}
              >
                {isPending ? 'Generating…' : act.label}
              </Button>
            );
          })}
        </div>
      </div>
      {error !== null && <ErrorState error={error} compact />}
    </div>
  );
}

/* --- Checkbox Item Component ---------------------------------------------- */

function CheckboxItem({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <label
      htmlFor={`check-${id}`}
      className={`${styles.checkboxCard} ${checked ? styles.checkboxCardSelected : ''}`}
    >
      <input
        type="checkbox"
        id={`check-${id}`}
        className={styles.checkboxInput}
        checked={checked}
        onChange={onChange}
      />
      <span className={styles.checkboxLabel}>{label}</span>
    </label>
  );
}

/* --- File Download Helper ------------------------------------------------- */

function downloadFile(file: ExportedFile): void {
  const url = URL.createObjectURL(file.blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = file.filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
