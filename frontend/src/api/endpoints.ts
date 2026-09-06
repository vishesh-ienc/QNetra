/**
 * Typed endpoint functions — one per route in docs/10_API_CONTRACT.md.
 * Components never build URLs themselves.
 */

import { request, upload, type Query } from './client';
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

export const api = {
  uploadArtifact: (file: File, name?: string) => {
    const form = new FormData();
    form.append('file', file);
    if (name) form.append('name', name);
    return upload<Artifact>('/artifacts/upload', form);
  },

  createScan: (body: { name?: string; artifact_id: string; target_type?: string }) =>
    request<Scan>('/scans', { method: 'POST', body }),

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
