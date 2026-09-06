import { useMemo } from 'react';
import { useAssets, useFinding } from '../../api/queries';
import { formatDateTime, formatPercent, NOT_AVAILABLE } from '../../lib/format';
import {
  confidenceLevelLabel,
  confidenceTone,
  discoveryMethodExplanation,
  discoveryMethodLabel,
} from '../../lib/labels';
import {
  Badge,
  Button,
  CodeEvidence,
  Drawer,
  DrawerSection,
  KeyValue,
  Meter,
  Prose,
} from '../../components/primitives';
import styles from './FindingDrawer.module.css';

interface FindingDrawerProps {
  scanId: string | null;
  findingId: string | null;
  onClose: () => void;
  onOpenAsset?: (assetId: string) => void;
}

export function FindingDrawer({
  scanId,
  findingId,
  onClose,
  onOpenAsset,
}: FindingDrawerProps) {
  const { data: finding, isLoading, error } = useFinding(scanId, findingId);

  // The asset this evidence was normalized into. `supporting_finding_ids` is the
  // backend's own traceability link — this is a lookup, not an inference.
  const { data: assetsPage } = useAssets(scanId, { page_size: 200 }, { enabled: Boolean(findingId) });
  const parentAsset = useMemo(() => {
    if (!findingId || !assetsPage) return null;
    return (
      assetsPage.data.find((asset) => asset.supporting_finding_ids.includes(findingId)) ?? null
    );
  }, [assetsPage, findingId]);

  if (!findingId) return null;

  return (
    <Drawer
      open
      onClose={onClose}
      eyebrow="Scanner evidence"
      title={finding ? (finding.suspected_algorithm ?? finding.raw_symbol) : 'Loading…'}
      subtitle={
        finding && (
          <>
            <span>{finding.artifact_category.replace(/_/g, ' ').toLowerCase()}</span>
            <span aria-hidden="true">·</span>
            <span className="mono">
              {finding.location.file_path}
              {finding.location.start_line !== null ? `:${finding.location.start_line}` : ''}
            </span>
          </>
        )
      }
      footer={
        parentAsset && onOpenAsset ? (
          <Button variant="primary" onClick={() => onOpenAsset(parentAsset.asset_id)}>
            Open crypto asset →
          </Button>
        ) : undefined
      }
    >
      {isLoading && <Prose>Loading evidence…</Prose>}
      {error && <Prose>{(error as Error).message}</Prose>}

      {finding && (
        <>
          <div className={styles.evidence}>
            <CodeEvidence
              filePath={finding.location.file_path}
              startLine={finding.location.start_line}
              endLine={finding.location.end_line}
              snippet={finding.location.snippet}
              symbol={finding.raw_symbol}
            />
          </div>

          <DrawerSection title="Detection">
            <KeyValue
              items={[
                {
                  label: 'Method',
                  value: (
                    <Badge tone="ACCENT" variant="outline">
                      {discoveryMethodLabel[finding.discovery_method] ?? finding.discovery_method}
                    </Badge>
                  ),
                },
                { label: 'Scanner', value: finding.scanner_name, mono: true },
                { label: 'Scanner version', value: finding.scanner_version, mono: true },
                {
                  label: 'Suspected algorithm',
                  value: finding.suspected_algorithm ?? NOT_AVAILABLE,
                  mono: Boolean(finding.suspected_algorithm),
                },
                {
                  label: 'Category',
                  value: finding.artifact_category.replace(/_/g, ' '),
                },
                {
                  label: 'Library hint',
                  value: finding.library_hint ?? NOT_AVAILABLE,
                  mono: Boolean(finding.library_hint),
                },
                {
                  label: 'Key size hint',
                  value:
                    finding.key_size_hint === null ? NOT_AVAILABLE : `${finding.key_size_hint} bits`,
                },
                {
                  label: 'Mode hint',
                  value: finding.mode_hint ?? NOT_AVAILABLE,
                  mono: Boolean(finding.mode_hint),
                },
                {
                  label: 'Curve hint',
                  value: finding.curve_hint ?? NOT_AVAILABLE,
                  mono: Boolean(finding.curve_hint),
                },
                { label: 'Discovered', value: formatDateTime(finding.discovered_at) },
                { label: 'Finding ID', value: finding.finding_id, mono: true },
              ]}
            />
            <div className={styles.methodNote}>
              <Prose>
                {discoveryMethodExplanation[finding.discovery_method] ??
                  'Discovery method description not available.'}
              </Prose>
            </div>
          </DrawerSection>

          <DrawerSection
            title="Confidence"
            description="How certain QNetra is that this cryptography is genuinely present. This is not a risk rating."
          >
            <div className={styles.confidenceHead}>
              <span className={`${styles.confidenceValue} numeric`}>
                {formatPercent(finding.confidence_score)}
              </span>
              <Badge tone={confidenceTone(finding.confidence_score)}>
                {confidenceLevelLabel[finding.confidence_level] ?? finding.confidence_level}
              </Badge>
            </div>
            <Meter
              value={finding.confidence_score}
              tone={confidenceTone(finding.confidence_score)}
            />
            <p className={styles.rationale}>{finding.confidence_rationale}</p>
          </DrawerSection>

          {(finding.symbol_name || finding.binary_format || finding.container_context) && (
            <DrawerSection title="Artifact context">
              <KeyValue
                items={[
                  ...(finding.binary_format
                    ? [{ label: 'Binary format', value: finding.binary_format }]
                    : []),
                  ...(finding.symbol_name
                    ? [{ label: 'Symbol', value: finding.symbol_name, mono: true }]
                    : []),
                  ...(finding.container_context
                    ? [
                        {
                          label: 'Container path',
                          value: finding.container_context.filesystem_path,
                          mono: true,
                        },
                        {
                          label: 'Image',
                          value: finding.container_context.image_reference ?? NOT_AVAILABLE,
                          mono: true,
                        },
                      ]
                    : []),
                ]}
              />
            </DrawerSection>
          )}

          <DrawerSection
            title="Normalization"
            description="Raw findings are merged into canonical crypto assets by core.normalization."
          >
            {parentAsset ? (
              <button
                type="button"
                className={styles.assetLink}
                onClick={() => onOpenAsset?.(parentAsset.asset_id)}
              >
                <span className={styles.assetLinkLabel}>Contributes to</span>
                <span className={`${styles.assetLinkValue} mono`}>
                  {parentAsset.algorithm}
                  {parentAsset.key_length_bits ? `-${parentAsset.key_length_bits}` : ''}
                </span>
                <span className={styles.assetLinkCount}>
                  {parentAsset.supporting_finding_ids.length} supporting finding
                  {parentAsset.supporting_finding_ids.length === 1 ? '' : 's'}
                </span>
              </button>
            ) : (
              <Prose>
                The canonical asset for this finding was not found in the current page of
                results.
              </Prose>
            )}
          </DrawerSection>
        </>
      )}
    </Drawer>
  );
}
