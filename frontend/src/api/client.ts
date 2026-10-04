const BASE_URL = '/api/v1';

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(`API Error ${status}: ${detail}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  body?: unknown;
  caseCode?: string | null;
  token?: string | null;
  idempotencyKey?: string | null;
}

export async function apiRequest<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const {
    method = 'GET',
    headers = {},
    body,
    caseCode,
    token,
    idempotencyKey,
  } = options;

  const requestHeaders: Record<string, string> = {
    'Accept': 'application/json',
    'Cache-Control': 'no-cache',
    ...headers,
  };

  // Invariant: Pass caseCode strictly via X-Case-Code header, never in URL
  if (caseCode) {
    requestHeaders['X-Case-Code'] = caseCode;
  }

  if (token) {
    requestHeaders['Authorization'] = `Bearer ${token}`;
  }

  if (idempotencyKey) {
    requestHeaders['Idempotency-Key'] = idempotencyKey;
  }

  let requestBody: BodyInit | undefined = undefined;
  if (body !== undefined) {
    if (body instanceof FormData) {
      requestBody = body;
      // Let browser set Content-Type with boundary
      delete requestHeaders['Content-Type'];
    } else {
      requestHeaders['Content-Type'] = 'application/json';
      requestBody = JSON.stringify(body);
    }
  }

  const url = `${BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    method,
    headers: requestHeaders,
    body: requestBody,
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errorJson = await response.json();
      if (typeof errorJson.detail === 'string') {
        errorDetail = errorJson.detail;
      } else if (Array.isArray(errorJson.detail)) {
        errorDetail = errorJson.detail.map((e: { msg?: string }) => e.msg || 'Validation error').join(', ');
      }
    } catch {
      // response was not JSON
    }
    throw new ApiError(response.status, errorDetail);
  }

  if (response.status === 204 || response.headers.get('content-length') === '0') {
    return {} as T;
  }

  return response.json();
}
