import { API_MODE } from './client';

export interface MoscaParameterSupport {
  /** True when the API recomputes the assessment for any parameter value. */
  continuous: boolean;
  /** Values the offline dataset carries engine output for, when not continuous. */
  xValues?: number[];
  zValues?: number[];
}

/**
 * What the current transport can actually recompute.
 *
 * The Mosca inequality is evaluated by core.mosca_engine. With the live API the
 * user may choose any parameters. Without it, only the pre-computed engine grid
 * is available, and the UI restricts the controls to those values rather than
 * evaluating anything itself.
 */
export async function getMoscaParameterSupport(): Promise<MoscaParameterSupport> {
  if (API_MODE === 'live') return { continuous: true };
  const { moscaGridSupport } = await import('../mocks/transport');
  const grid = await moscaGridSupport();
  return { continuous: false, xValues: grid.x, zValues: grid.z };
}
