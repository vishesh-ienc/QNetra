import { useMemo } from 'react';
import { useAsset, useMosca, useRecommendations, useRisk } from '../../api/queries';
import type {
  CryptoAsset,
  MoscaAssessment,
  PqcRecommendation,
  RiskAssessment,
} from '../../api/types';

export interface AssetDossier {
  asset: CryptoAsset | null;
  risk: RiskAssessment | null;
  mosca: MoscaAssessment | null;
  recommendation: PqcRecommendation | null;
  isLoading: boolean;
  error: Error | null;
}

/**
 * Joins the four backend views of one asset by `asset_id`.
 *
 * This is a join, not an analysis: every field displayed downstream was computed
 * by the engine that owns it (core.risk_engine, core.mosca_engine,
 * core.recommendation_engine, core.classification).
 */
export function useAssetDossier(
  scanId: string | null,
  assetId: string | null,
  moscaX: number | null = null,
  moscaZ: number | null = null,
): AssetDossier {
  const assetQuery = useAsset(scanId, assetId);
  const riskQuery = useRisk(scanId);
  const moscaQuery = useMosca(scanId, moscaX, moscaZ);
  const recommendationQuery = useRecommendations(scanId);

  return useMemo(() => {
    const risk =
      riskQuery.data?.assessments.find((entry) => entry.asset_id === assetId) ?? null;
    const mosca =
      moscaQuery.data?.assessments.find((entry) => entry.asset_id === assetId) ?? null;
    const recommendation =
      recommendationQuery.data?.recommendations.find((entry) => entry.asset_id === assetId) ??
      null;

    return {
      asset: assetQuery.data ?? null,
      risk,
      mosca,
      recommendation,
      isLoading: assetQuery.isLoading,
      error: (assetQuery.error as Error | null) ?? null,
    };
  }, [
    assetId,
    assetQuery.data,
    assetQuery.error,
    assetQuery.isLoading,
    riskQuery.data,
    moscaQuery.data,
    recommendationQuery.data,
  ]);
}
