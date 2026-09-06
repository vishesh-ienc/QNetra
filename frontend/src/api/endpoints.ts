/**
 * Typed endpoint functions — one per route in docs/10_API_CONTRACT.md.
 * Components never build URLs themselves.
 */

import { ApiError, API_BASE_URL, API_MODE, NotImplementedByBackendError, request, upload, type Query } from './client';
import type {
  CbomDocument,
  CryptoAsset,
  Finding,
  MoscaReport,
  MoscaRequest,
  Paginated,
  RecommendationReport,
  RiskReport,
  Scan,
} from './types';

export interface ListParams extends Query {
  page?: number;
  page_size?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  q?: string;
}

export interface FindingsParams extends ListParams {
  algorithm?: string;
  category?: string;
  scanner?: string;
  method?: string;
  min_confidence?: number;
}

export interface AssetsParams extends ListParams {
  algorithm?: string;
  primitive_type?: string;
  severity?: string;
  library?: string;
  quantum_threat_type?: string;
  quantum_vulnerable?: boolean;
}

export interface Artifact {
  artifact_id: string;
  name: string | null;
  artifact_type: string | null;
  filename: string;
  file_size_bytes: number;
  status: string;
  uploaded_at: string;
  expires_at: string | null;
}

export interface ExportedFile {
  content: string;
  filename: string;
  mediaType: string;
}

/**
 * File-download endpoints (docs/10 §10, §15) return a raw stream, not a JSON
 * envelope, so they bypass the generic `request()` helper. Only meaningful in
 * live mode: the mock dataset speaks the JSON contract, not the file-download
 * contract.
 */
async function fetchExportedFile(path: string, notice: string): Promise<ExportedFile> {
  if (API_MODE !== 'live') {
    throw new NotImplementedByBackendError(notice);
  }
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new ApiError(
      payload?.error?.code ?? 'EXPORT_FAILED',
      payload?.error?.message ?? `Export failed with status ${response.status}.`,
      response.status,
    );
  }
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = /filename="?([^";]+)"?/.exec(disposition);
  return {
    content: await response.text(),
    filename: match?.[1] ?? 'download',
    mediaType: response.headers.get('content-type') ?? 'application/octet-stream',
  };
}

function exportCbom(scanId: string, format: 'json' | 'xml'): Promise<ExportedFile> {
  return fetchExportedFile(
    `/scans/${scanId}/cbom/export?format=${format}`,
    'CBOM file export requires the live QNetra API. Set VITE_API_MODE=live and start the ' +
      "backend, or use the CBOM view's in-browser JSON download in the meantime.",
  );
}

/** Server-composed exports (docs/10 §15): the full envelope, the asset-inventory CSV, or PDF. */
function exportScan(scanId: string, format: 'json' | 'csv' | 'pdf'): Promise<ExportedFile> {
  return fetchExportedFile(
    `/scans/${scanId}/export?format=${format}`,
    'This export requires the live QNetra API. Set VITE_API_MODE=live and start the backend.',
  );
}

export const api = {
  exportCbom,
  exportScan,
  uploadArtifact: (file: File, name?: string) => {
    const form = new FormData();
    form.append('file', file);
    if (name) form.append('name', name);
    return upload<Artifact>('/artifacts/upload', form);
  },

  createScan: (body: {
    name?: string;
    artifact_id: string;
    target_type?: string;
    mosca_params?: {
      data_shelf_life_years_x?: number;
      migration_time_years_y?: number;
      quantum_threat_horizon_years_z?: number;
    };
  }) => request<Scan>('/scans', { method: 'POST', body }),

  listScans: () => request<Paginated<Scan>>('/scans'),

  getScan: (scanId: string) => request<Scan>(`/scans/${scanId}`),

  listFindings: (scanId: string, params: FindingsParams = {}) =>
    request<Paginated<Finding>>(`/scans/${scanId}/findings`, { params }),

  getFinding: (scanId: string, findingId: string) =>
    request<Finding>(`/scans/${scanId}/findings/${findingId}`),

  listAssets: (scanId: string, params: AssetsParams = {}) =>
    request<Paginated<CryptoAsset>>(`/scans/${scanId}/assets`, { params }),

  getAsset: (scanId: string, assetId: string) =>
    request<CryptoAsset>(`/scans/${scanId}/assets/${assetId}`),

  getRisk: (scanId: string) => request<RiskReport>(`/scans/${scanId}/risk`),

  getRecommendations: (scanId: string) =>
    request<RecommendationReport>(`/scans/${scanId}/recommendations`),

  getCbom: (scanId: string) => request<CbomDocument>(`/scans/${scanId}/cbom`),

  getMosca: (scanId: string, params: Partial<MoscaRequest> = {}) =>
    request<MoscaReport>(`/scans/${scanId}/mosca`, { params: params as Query }),

  /** Engine-side recomputation of X + Y > Z. The frontend never evaluates it. */
  assessMosca: (scanId: string, body: MoscaRequest) =>
    request<MoscaReport>(`/scans/${scanId}/mosca`, { method: 'POST', body }),
};
