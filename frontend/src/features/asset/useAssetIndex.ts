import { useMemo } from 'react';
import { useMosca, useRecommendations } from '../../api/queries';
import type { MoscaAssessment, PqcRecommendation } from '../../api/types';

export interface AssetIndex {
  moscaByAsset: Map<string, MoscaAssessment>;
  recommendationByAsset: Map<string, PqcRecommendation>;
  isLoading: boolean;
}

/**
 * Lookup maps keyed by `asset_id`, so a table row can show the urgency and the
 * recommended replacement the engines already produced for that asset.
 */
export function useAssetIndex(
  scanId: string | null,
  moscaX: number | null = null,
  moscaZ: number | null = null,
): AssetIndex {
  const moscaQuery = useMosca(scanId, moscaX, moscaZ);
  const recommendationQuery = useRecommendations(scanId);

  return useMemo(() => {
    const moscaByAsset = new Map<string, MoscaAssessment>();
    for (const assessment of moscaQuery.data?.assessments ?? []) {
      moscaByAsset.set(assessment.asset_id, assessment);
    }
    const recommendationByAsset = new Map<string, PqcRecommendation>();
    for (const recommendation of recommendationQuery.data?.recommendations ?? []) {
      recommendationByAsset.set(recommendation.asset_id, recommendation);
    }
    return {
      moscaByAsset,
      recommendationByAsset,
      isLoading: moscaQuery.isLoading || recommendationQuery.isLoading,
    };
  }, [
    moscaQuery.data,
    moscaQuery.isLoading,
    recommendationQuery.data,
    recommendationQuery.isLoading,
  ]);
}
