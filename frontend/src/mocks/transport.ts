/**
 * Fixture-backed mock transport.
 *
 * `backend/` (the Phase 4 FastAPI gateway) is not implemented, so there is no
 * live `/api/v1` to develop against. This transport answers the exact request
 * contract the real API will answer, using JSON fixtures produced by running the
 * real QNetra pipeline over `samples/` — see `frontend/tools/generate_fixtures.py`.
 *
 * IMPORTANT
 *   - No security intelligence is computed here. Filtering, sorting, searching and
 *     pagination are presentation concerns and are exactly what the real API will
 *     do server-side.
 *   - Anything the backend genuinely cannot do yet (starting a scan, recomputing
 *     Mosca for arbitrary parameters) raises NotImplementedByBackendError so the
 *     UI can say so honestly instead of faking a result.
 */

import {
  ApiError,
  NotImplementedByBackendError,
  type Query,
  registerMockTransport,
} from '../api/client';
import type {
  CbomDocument,
  CryptoAsset,
  Finding,
  MoscaReport,
  Paginated,
  RecommendationReport,
  RiskReport,
  Scan,
} from '../api/types';

const LATENCY_MS = 180;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/* --- Lazily loaded fixtures ---------------------------------------------- */

const load = {
  scan: () => import('./fixtures/scan.json').then((m) => m.default as unknown as Scan),
  findings: () =>
    import('./fixtures/findings.json').then((m) => m.default as unknown as Finding[]),
  assets: () =>
    import('./fixtures/assets.json').then((m) => m.default as unknown as CryptoAsset[]),
  risk: () => import('./fixtures/risk.json').then((m) => m.default as unknown as RiskReport),
  mosca: () => import('./fixtures/mosca.json').then((m) => m.default as unknown as MoscaReport),
  recommendations: () =>
    import('./fixtures/recommendations.json').then(
      (m) => m.default as unknown as RecommendationReport,
    ),
  cbom: () => import('./fixtures/cbom.json').then((m) => m.default as unknown as CbomDocument),
  moscaGridIndex: () =>
    import('./fixtures/mosca-grid/index.json').then(
      (m) => m.default as unknown as MoscaGridIndex,
    ),
};

interface MoscaGridIndex {
  x_values: number[];
  z_values: number[];
  entries: {
    key: string;
    data_shelf_life_years_x: number;
    quantum_threat_horizon_years_z: number;
    mosca_triggered_assets: number;
  }[];
}

const gridModules = import.meta.glob('./fixtures/mosca-grid/x*.json');

/** Parameter combinations the pre-computed engine grid covers in mock mode. */
export async function moscaGridSupport(): Promise<{ x: number[]; z: number[] }> {
  const index = await load.moscaGridIndex();
  return { x: index.x_values, z: index.z_values };
}

/* --- Generic list shaping (what the real API does server-side) ------------ */

function num(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function paginate<T>(rows: T[], params: Query): Paginated<T> {
  const page = Math.max(1, num(params.page) || 1);
  const pageSize = Math.min(200, Math.max(1, num(params.page_size) || 50));
  const total = rows.length;
  const start = (page - 1) * pageSize;
  return {
    data: rows.slice(start, start + pageSize),
    pagination: {
      page,
      page_size: pageSize,
      total_items: total,
      total_pages: Math.max(1, Math.ceil(total / pageSize)),
    },
  };
}

function compare(a: unknown, b: unknown): number {
  if (a === null || a === undefined) return b === null || b === undefined ? 0 : 1;
  if (b === null || b === undefined) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

function sortRows<T extends Record<string, unknown>>(rows: T[], params: Query): T[] {
  const key = params.sort ? String(params.sort) : null;
  if (!key) return rows;
  const direction = String(params.order ?? 'desc') === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => compare(a[key], b[key]) * direction);
}

function matches(haystack: unknown, needle: string): boolean {
  return String(haystack ?? '').toLowerCase().includes(needle);
}

/* --- Route handlers ------------------------------------------------------- */

async function findingsList(params: Query): Promise<Paginated<Finding>> {
  const all = await load.findings();
  const search = String(params.q ?? '').trim().toLowerCase();

  const filtered = all.filter((f) => {
    if (params.algorithm && f.suspected_algorithm !== params.algorithm) return false;
    if (params.category && f.artifact_category !== params.category) return false;
    if (params.method && f.discovery_method !== params.method) return false;
    if (params.scanner && !matches(f.scanner_name, String(params.scanner).toLowerCase()))
      return false;
    if (params.min_confidence && f.confidence_score < num(params.min_confidence)) return false;
    if (
      search &&
      !matches(f.raw_symbol, search) &&
      !matches(f.location.file_path, search) &&
      !matches(f.suspected_algorithm, search) &&
      !matches(f.library_hint, search)
    )
      return false;
    return true;
  });

  const sorted = params.sort
    ? sortRows(filtered as unknown as Record<string, unknown>[], params)
    : [...filtered].sort((a, b) => b.confidence_score - a.confidence_score);

  return paginate(sorted as unknown as Finding[], params);
}

async function assetsList(params: Query): Promise<Paginated<CryptoAsset>> {
  const all = await load.assets();
  const search = String(params.q ?? '').trim().toLowerCase();

  const filtered = all.filter((a) => {
    if (params.algorithm && a.algorithm !== params.algorithm) return false;
    if (params.primitive_type && a.primitive_type !== params.primitive_type) return false;
    if (params.severity && a.risk_severity !== params.severity) return false;
    if (params.library && a.implementation_library !== params.library) return false;
    if (params.quantum_threat_type && a.quantum_threat_type !== params.quantum_threat_type)
      return false;
    if (params.quantum_vulnerable !== undefined && params.quantum_vulnerable !== '') {
      const want = String(params.quantum_vulnerable) === 'true';
      if (a.quantum_vulnerable !== want) return false;
    }
    if (
      search &&
      !matches(a.algorithm, search) &&
      !matches(a.location.file_path, search) &&
      !matches(a.implementation_library, search) &&
      !matches(a.primitive_type, search)
    )
      return false;
    return true;
  });

  const sorted = params.sort
    ? sortRows(filtered as unknown as Record<string, unknown>[], params)
    : [...filtered].sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1));

  return paginate(sorted as unknown as CryptoAsset[], params);
}

async function moscaForParameters(params: Query): Promise<MoscaReport> {
  const baseline = await load.mosca();
  const x = params.data_shelf_life_years_x;
  const z = params.quantum_threat_horizon_years_z;

  if (x === undefined && z === undefined) return baseline;

  const xValue = x === undefined ? baseline.parameters.data_shelf_life_years_x : num(x);
  const zValue =
    z === undefined ? baseline.parameters.quantum_threat_horizon_years_z : num(z);

  if (
    xValue === baseline.parameters.data_shelf_life_years_x &&
    zValue === baseline.parameters.quantum_threat_horizon_years_z
  ) {
    return baseline;
  }

  const key = `./fixtures/mosca-grid/x${formatKey(xValue)}-z${formatKey(zValue)}.json`;
  const loader = gridModules[key];
  if (!loader) {
    throw new NotImplementedByBackendError(
      `Mosca recomputation for X=${xValue} / Z=${zValue} requires the QNetra API. ` +
        'The offline dataset only carries engine output for the pre-computed parameter grid.',
    );
  }
  const module = (await loader()) as { default: MoscaReport };
  return module.default;
}

function formatKey(value: number | null): string {
  if (value === null) return 'null';
  return Number.isInteger(value) ? String(value) : String(value);
}

/* --- Router --------------------------------------------------------------- */

const SEGMENTS = (path: string) => path.split('/').filter(Boolean);

async function route(path: string, params: Query, init?: RequestInit): Promise<unknown> {
  const method = init?.method ?? 'GET';
  const seg = SEGMENTS(path);
  const body: Query = init?.body ? JSON.parse(String(init.body)) : {};

  if (seg[0] === 'artifacts' || (seg[0] === 'scans' && method === 'POST' && seg.length === 1)) {
    throw new NotImplementedByBackendError(
      'Starting a scan requires the QNetra API service (backend/), which is not implemented yet. ' +
        'This session is showing a pre-computed dataset produced by running the real QNetra ' +
        'pipeline over the repository sample targets.',
    );
  }

  if (seg[0] !== 'scans') {
    throw new ApiError('NOT_FOUND', `No mock route for ${method} ${path}.`, 404);
  }

  // GET /scans
  if (seg.length === 1) {
    const scan = await load.scan();
    return { data: [scan], pagination: { page: 1, page_size: 50, total_items: 1, total_pages: 1 } };
  }

  const resource = seg[2];

  // GET /scans/{id}
  if (seg.length === 2) return load.scan();

  switch (resource) {
    case 'progress': {
      const scan = await load.scan();
      return {
        scan_id: scan.scan_id,
        status: scan.status,
        current_stage: scan.current_stage,
        ...scan.progress,
      };
    }
    case 'findings': {
      if (seg.length === 4) {
        const all = await load.findings();
        const found = all.find((f) => f.finding_id === seg[3]);
        if (!found) throw new ApiError('FINDING_NOT_FOUND', `Finding ${seg[3]} does not exist.`, 404);
        return found;
      }
      return findingsList(params);
    }
    case 'assets': {
      if (seg.length === 4) {
        const all = await load.assets();
        const found = all.find((a) => a.asset_id === seg[3]);
        if (!found) throw new ApiError('ASSET_NOT_FOUND', `Asset ${seg[3]} does not exist.`, 404);
        return found;
      }
      return assetsList(params);
    }
    case 'risk':
      return load.risk();
    case 'recommendations':
      return load.recommendations();
    case 'cbom':
      return load.cbom();
    case 'mosca':
      if (method === 'POST') return moscaForParameters(body);
      return moscaForParameters(params);
    case 'export':
      throw new NotImplementedByBackendError(
        'Server-side report export requires the QNetra API service (backend/).',
      );
    default:
      throw new ApiError('NOT_FOUND', `No mock route for ${method} ${path}.`, 404);
  }
}

export function installMockTransport(): void {
  registerMockTransport(async (path, params, init) => {
    await delay(LATENCY_MS);
    return route(path, params, init);
  });
}
