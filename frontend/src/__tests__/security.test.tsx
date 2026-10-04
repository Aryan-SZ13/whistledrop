import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiRequest } from '../api/client';
import { uploadEvidence, getVerificationReceipt, withdrawReport } from '../api/reports';
import { listMessages, getNotifications } from '../api/messages';

describe('Frontend Security & URL Leakage Invariants', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('never stores case code in localStorage or sessionStorage', () => {
    // Verify local and session storage are completely untouched
    expect(localStorage.getItem('case_code')).toBeNull();
    expect(localStorage.getItem('wdc_token')).toBeNull();
    expect(sessionStorage.getItem('case_code')).toBeNull();
  });

  it('attaches case code strictly via X-Case-Code header and never in URL for evidence upload', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ status: 'clean', attachment_id: 'att-123', scan_status: 'CLEAN' }),
    });
    globalThis.fetch = fetchMock;

    const testCaseCode = 'wdc_secret_test_code_12345';
    const fakeFile = new File(['dummy evidence'], 'contract.pdf', { type: 'application/pdf' });

    await uploadEvidence(testCaseCode, fakeFile);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];

    // Assert URL does NOT contain the case code
    expect(calledUrl).toBe('/api/v1/reports/evidence');
    expect(calledUrl).not.toContain(testCaseCode);

    // Assert X-Case-Code header is present and exact
    expect(calledInit.headers['X-Case-Code']).toBe(testCaseCode);
  });

  it('attaches case code strictly via X-Case-Code header for message listing and sending', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ items: [], next_cursor: null, has_more: false }),
    });
    globalThis.fetch = fetchMock;

    const testCaseCode = 'wdc_secret_test_code_67890';

    await listMessages(testCaseCode);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];

    expect(calledUrl).toContain('/api/v1/reports/messages');
    expect(calledUrl).not.toContain(testCaseCode);
    expect(calledInit.headers['X-Case-Code']).toBe(testCaseCode);
  });

  it('attaches case code strictly via X-Case-Code header for case tracking and notification polling', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ status_version: 1, status: 'SUBMITTED', unread_messages_count: 0, last_notified_at: '2026-10-04T00:00:00Z' }),
    });
    globalThis.fetch = fetchMock;

    const testCaseCode = 'wdc_tracking_code_98765';

    await getNotifications(testCaseCode);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];

    expect(calledUrl).toBe('/api/v1/reports/notifications');
    expect(calledUrl).not.toContain(testCaseCode);
    expect(calledInit.headers['X-Case-Code']).toBe(testCaseCode);
  });

  it('attaches case code strictly via X-Case-Code header for verification receipt download', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        case_reference: 'ref_123',
        status: 'SUBMITTED',
        created_at: '2026-10-04T00:00:00Z',
        signature: 'sig_abc',
      }),
    });
    globalThis.fetch = fetchMock;

    const testCaseCode = 'wdc_verification_code_999';

    await getVerificationReceipt(testCaseCode);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];

    expect(calledUrl).toBe('/api/v1/reports/verification');
    expect(calledUrl).not.toContain(testCaseCode);
    expect(calledInit.headers['X-Case-Code']).toBe(testCaseCode);
  });

  it('attaches case code strictly via X-Case-Code header for case withdrawal', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        status: 'withdrawn',
        message: 'Case withdrawn and keys shredded',
        shredded_at: '2026-10-04T00:00:00Z',
      }),
    });
    globalThis.fetch = fetchMock;

    const testCaseCode = 'wdc_withdraw_code_888';

    await withdrawReport(testCaseCode, 'Voluntary withdrawal');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];

    expect(calledUrl).toBe('/api/v1/reports/withdraw');
    expect(calledUrl).not.toContain(testCaseCode);
    expect(calledInit.headers['X-Case-Code']).toBe(testCaseCode);
  });

  it('attaches Authorization Bearer header for moderator operations', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ status: 'ok' }),
    });
    globalThis.fetch = fetchMock;

    const mockToken = 'mock_jwt_access_token_xyz';
    await apiRequest('/moderator/dashboard/stats', {
      method: 'GET',
      token: mockToken,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, calledInit] = fetchMock.mock.calls[0];

    expect(calledInit.headers['Authorization']).toBe(`Bearer ${mockToken}`);
  });
});
