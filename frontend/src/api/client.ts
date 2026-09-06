/**
 * QNetra API client.
 *
 * Every network call in the application goes through `request()`. There are no
 * ad-hoc `fetch` calls in components.
 *
 * Two transports:
 *   live (default) — talks to the FastAPI gateway at `VITE_API_BASE_URL`
 *          (default `/api/v1`, proxied by Vite to http://127.0.0.1:8000 in dev).
 *   mock — serves fixtures generated from real QNetra engine output by
 *          `frontend/tools/generate_fixtures.py`. Useful for UI work with no
 *          backend running. Speaks the identical contract as live, so switching
 *          modes is configuration only, never a code change.
 */

import type { ApiErrorBody } from './types';

export type ApiMode = 'live' | 'mock';

const RAW_MODE = import.meta.env.VITE_API_MODE as string | undefined;

export const API_MODE: ApiMode = RAW_MODE === 'mock' ? 'mock' : 'live';

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1';

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details: unknown;

  constructor(code: string, message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

/** Thrown when the UI asks for something the current backend genuinely cannot provide. */
export class NotImplementedByBackendError extends ApiError {
  constructor(message: string) {
    super('NOT_IMPLEMENTED', message, 501);
    this.name = 'NotImplementedByBackendError';
  }
}

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue>;

export function buildQuery(params: Query = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : '';
}

type MockTransport = (
  path: string,
  params: Query,
  init?: RequestInit,
) => Promise<unknown>;

let mockTransport: MockTransport | null = null;

/** Registered once at boot when running in mock mode. */
export function registerMockTransport(transport: MockTransport): void {
  mockTransport = transport;
}

export interface RequestOptions {
  params?: Query;
  method?: 'GET' | 'POST' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
}

/** Multipart upload. Same transport switch as `request`, different body encoding. */
export async function upload<T>(path: string, formData: FormData): Promise<T> {
  if (API_MODE === 'mock') {
    if (!mockTransport) {
      throw new ApiError(
        'MOCK_TRANSPORT_UNAVAILABLE',
        'Mock transport was not registered before the first request.',
        500,
      );
    }
    return mockTransport(path, {}, { method: 'POST' }) as Promise<T>;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { method: 'POST', body: formData });
  } catch (cause) {
    throw new ApiError(
      'NETWORK_ERROR',
      'Could not reach the QNetra API. Check that the backend service is running.',
      0,
      cause,
    );
  }

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const err = (payload as ApiErrorBody | null)?.error;
    throw new ApiError(
      err?.code ?? 'UPLOAD_FAILED',
      err?.message ?? `Upload failed with status ${response.status}.`,
      response.status,
      err?.details,
    );
  }
  return payload as T;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { params = {}, method = 'GET', body, signal } = options;

  if (API_MODE === 'mock') {
    if (!mockTransport) {
      throw new ApiError(
        'MOCK_TRANSPORT_UNAVAILABLE',
        'Mock transport was not registered before the first request.',
        500,
      );
    }
    return mockTransport(path, params, {
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
    }) as Promise<T>;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}${buildQuery(params)}`, {
      method,
      signal,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (cause) {
    throw new ApiError(
      'NETWORK_ERROR',
      'Could not reach the QNetra API. Check that the backend service is running.',
      0,
      cause,
    );
  }

  if (response.status === 204) return undefined as T;

  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    const err = (payload as ApiErrorBody | null)?.error;
    throw new ApiError(
      err?.code ?? 'UNEXPECTED_ERROR',
      err?.message ?? `Request failed with status ${response.status}.`,
      response.status,
      err?.details,
    );
  }

  return payload as T;
}
