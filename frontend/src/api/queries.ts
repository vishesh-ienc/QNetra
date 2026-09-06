/**
 * React Query hooks. All server state flows through these.
 */

import { useQuery, type UseQueryOptions } from '@tanstack/react-query';
import { api, type AssetsParams, type FindingsParams } from './endpoints';
import type {
  CbomDocument,
  CryptoAsset,
  Finding,
  MoscaReport,
  Paginated,
  RecommendationReport,
  RiskReport,
  Scan,
} from './types';

export const queryKeys = {
  scans: ['scans'] as const,
  scan: (id: string) => ['scan', id] as const,
  findings: (id: string, params: FindingsParams) => ['findings', id, params] as const,
  finding: (id: string, fid: string) => ['finding', id, fid] as const,
  assets: (id: string, params: AssetsParams) => ['assets', id, params] as const,
  asset: (id: string, aid: string) => ['asset', id, aid] as const,
  risk: (id: string) => ['risk', id] as const,
  recommendations: (id: string) => ['recommendations', id] as const,
  cbom: (id: string) => ['cbom', id] as const,
  mosca: (id: string, x: number | null, z: number | null) => ['mosca', id, x, z] as const,
};

type Opts<T> = Omit<UseQueryOptions<T, Error, T>, 'queryKey' | 'queryFn'>;

export const useScans = () =>
  useQuery({ queryKey: queryKeys.scans, queryFn: () => api.listScans() });

export const useScan = (scanId: string | null) =>
  useQuery<Scan>({
    queryKey: queryKeys.scan(scanId ?? ''),
    queryFn: () => api.getScan(scanId as string),
    enabled: Boolean(scanId),
  });

export const useFindings = (
  scanId: string | null,
  params: FindingsParams = {},
  opts: Opts<Paginated<Finding>> = {},
) =>
  useQuery<Paginated<Finding>>({
    queryKey: queryKeys.findings(scanId ?? '', params),
    queryFn: () => api.listFindings(scanId as string, params),
    enabled: Boolean(scanId),
    placeholderData: (previous) => previous,
    ...opts,
  });

export const useFinding = (scanId: string | null, findingId: string | null) =>
  useQuery<Finding>({
    queryKey: queryKeys.finding(scanId ?? '', findingId ?? ''),
    queryFn: () => api.getFinding(scanId as string, findingId as string),
    enabled: Boolean(scanId && findingId),
  });

export const useAssets = (
  scanId: string | null,
  params: AssetsParams = {},
  opts: Opts<Paginated<CryptoAsset>> = {},
) =>
  useQuery<Paginated<CryptoAsset>>({
    queryKey: queryKeys.assets(scanId ?? '', params),
    queryFn: () => api.listAssets(scanId as string, params),
    enabled: Boolean(scanId),
    placeholderData: (previous) => previous,
    ...opts,
  });

export const useAsset = (scanId: string | null, assetId: string | null) =>
  useQuery<CryptoAsset>({
    queryKey: queryKeys.asset(scanId ?? '', assetId ?? ''),
    queryFn: () => api.getAsset(scanId as string, assetId as string),
    enabled: Boolean(scanId && assetId),
  });

export const useRisk = (scanId: string | null) =>
  useQuery<RiskReport>({
    queryKey: queryKeys.risk(scanId ?? ''),
    queryFn: () => api.getRisk(scanId as string),
    enabled: Boolean(scanId),
  });

export const useRecommendations = (scanId: string | null) =>
  useQuery<RecommendationReport>({
    queryKey: queryKeys.recommendations(scanId ?? ''),
    queryFn: () => api.getRecommendations(scanId as string),
    enabled: Boolean(scanId),
  });

export const useCbom = (scanId: string | null) =>
  useQuery<CbomDocument>({
    queryKey: queryKeys.cbom(scanId ?? ''),
    queryFn: () => api.getCbom(scanId as string),
    enabled: Boolean(scanId),
  });

/**
 * Mosca assessment. `x`/`z` null means "whatever the engine last computed".
 * The inequality itself is always evaluated by core.mosca_engine, never here.
 */
export const useMosca = (
  scanId: string | null,
  x: number | null = null,
  z: number | null = null,
) =>
  useQuery<MoscaReport>({
    queryKey: queryKeys.mosca(scanId ?? '', x, z),
    queryFn: () =>
      api.getMosca(scanId as string, {
        ...(x === null ? {} : { data_shelf_life_years_x: x }),
        ...(z === null ? {} : { quantum_threat_horizon_years_z: z }),
      }),
    enabled: Boolean(scanId),
    placeholderData: (previous) => previous,
    retry: false,
  });
