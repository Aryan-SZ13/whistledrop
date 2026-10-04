import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';

interface InterceptedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

describe('JSDOM + Intercepted Fetch Adversarial Network & Storage Audit (Simulated Browser Environment)', () => {
  const interceptedRequests: InterceptedRequest[] = [];
  const testCaseCode = 'wdc_live_audit_secret_token_1234567890';

  beforeEach(() => {
    vi.restoreAllMocks();
    interceptedRequests.length = 0;
    localStorage.clear();
    sessionStorage.clear();

    // Mock global fetch in jsdom to capture every detail of outgoing HTTP calls
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      const headersRecord: Record<string, string> = {};
      if (init?.headers) {
        if (init.headers instanceof Headers) {
          init.headers.forEach((v, k) => {
            headersRecord[k] = v;
          });
        } else if (Array.isArray(init.headers)) {
          init.headers.forEach(([k, v]) => {
            headersRecord[k] = v;
          });
        } else {
          Object.assign(headersRecord, init.headers);
        }
      }

      interceptedRequests.push({
        url: url.toString(),
        method: init?.method || 'GET',
        headers: headersRecord,
        body: init?.body,
      });

      // Mock specific responses matching real WhistleDrop backend contracts
      if (url.includes('/api/v1/reports') && init?.method === 'POST') {
        if (url.includes('/evidence')) {
          return {
            ok: true,
            status: 201,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ status: 'clean', attachment_id: 'att-uuid-1', scan_status: 'CLEAN' }),
          };
        }
        if (url.includes('/messages/read')) {
          return {
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ status: 'ok' }),
          };
        }
        if (url.includes('/messages')) {
          return {
            ok: true,
            status: 201,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              id: 'msg_client_test_1',
              sender_type: 'REPORTER',
              content: 'Follow-up disclosure text',
              created_at: '2026-10-04T12:00:00Z',
            }),
          };
        }
        if (url.includes('/withdraw')) {
          return {
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              status: 'withdrawn',
              message: 'Report withdrawn and encryption keys destroyed',
              shredded_at: '2026-10-04T12:00:00Z',
            }),
          };
        }
        // Core report submission
        return {
          ok: true,
          status: 201,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            case_code: testCaseCode,
            status: 'SUBMITTED',
            created_at: '2026-10-04T10:00:00Z',
          }),
        };
      }

      if (url.includes('/api/v1/reports/messages')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            items: [
              {
                id: 'msg_investigator_1',
                sender_type: 'MODERATOR',
                content: 'Case securely received and under preliminary review.',
                created_at: '2026-10-04T10:05:00Z',
              },
            ],
            next_cursor: null,
            has_more: false,
          }),
        };
      }

      if (url.includes('/api/v1/reports/notifications')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            status_version: 1,
            status: 'SUBMITTED',
            unread_messages_count: 0,
            last_notified_at: '2026-10-04T10:00:00Z',
          }),
        };
      }

      if (url.includes('/api/v1/reports/verification')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            case_reference: 'ref_sha256_pseudonym',
            status: 'SUBMITTED',
            created_at: '2026-10-04T10:00:00Z',
            resolved_at: null,
            withdrawn_at: null,
            evidence_count: 1,
            status_updates_count: 0,
            key_id: 'ed25519:2026-v1',
            signature: 'sig_ed25519_verified',
          }),
        };
      }

      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ status: 'ok' }),
      };
    });
  });

  it('executes full anonymous lifecycle and verifies zero case code in URLs or storage', async () => {
    render(<App />);

    // 1. Submit Report
    const titleInput = screen.getByPlaceholderText('Brief summary of the incident or misconduct');
    const descInput = screen.getByPlaceholderText(
      'Provide factual details: what occurred, timeline, entities involved, and locations. Do NOT include your own personal identity.'
    );
    const submitBtn = screen.getByText('Submit Confidential Report', { selector: 'button' });

    fireEvent.change(titleInput, { target: { value: 'Procurement Irregularities in Dept B' } });
    fireEvent.change(descInput, {
      target: { value: 'Unapproved vendor payments identified exceeding authorized procurement thresholds.' },
    });
    fireEvent.click(submitBtn);

    // 2. Verify Case Code Presentation in UI
    await waitFor(() => {
      expect(screen.getByText('Report Securely Registered')).toBeDefined();
      expect(screen.getByText(testCaseCode)).toBeDefined();
    });

    // 3. Confirm Saved & Proceed to Track Portal
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);

    const proceedBtn = screen.getByText('Access Case Tracking Portal');
    fireEvent.click(proceedBtn);

    // 4. Verify Tracking Portal is Active
    await waitFor(() => {
      expect(screen.getByText('Case Tracking Portal')).toBeDefined();
      expect(screen.getAllByText('Case securely received and under preliminary review.').length).toBeGreaterThanOrEqual(1);
    });

    // 5. Send an Anonymous Follow-Up Message
    const msgInput = screen.getByPlaceholderText('Send an anonymous message to the investigation team...');
    fireEvent.change(msgInput, { target: { value: 'Follow-up disclosure text' } });
    const sendMsgBtn = msgInput.closest('form')?.querySelector('button[type="submit"]') as HTMLElement;
    fireEvent.click(sendMsgBtn);

    await waitFor(() => {
      expect(screen.getAllByText('Follow-up disclosure text').length).toBeGreaterThanOrEqual(1);
    });

    // 6. Download Verification Receipt
    const receiptBtn = screen.getByText('Download Cryptographic Receipt');
    fireEvent.click(receiptBtn);

    await waitFor(() => {
      expect(screen.getByText('Asymmetrically Signed Receipt (Ed25519)')).toBeDefined();
    });

    // 7. Withdraw Report
    const withdrawBtn = screen.getByText('Withdraw Report & Irrevocably Shred Keys');
    fireEvent.click(withdrawBtn);

    const confirmShredBtn = screen.getByText('Confirm & Shred All Data');
    fireEvent.click(confirmShredBtn);

    await waitFor(() => {
      expect(screen.getByText(/Case Successfully Withdrawn/)).toBeDefined();
    });

    // =========================================================================
    // STRICT ADVERSARIAL AUDIT OF ALL CAPTURED NETWORK REQUESTS
    // =========================================================================
    expect(interceptedRequests.length).toBeGreaterThanOrEqual(4);

    for (const req of interceptedRequests) {
      const urlObj = new URL(req.url, 'http://localhost:3000');

      // Assertion A: Case code MUST NOT be in the request URL anywhere (path, query, fragment)
      expect(req.url).not.toContain(testCaseCode);
      expect(urlObj.pathname).not.toContain(testCaseCode);
      expect(urlObj.searchParams.get('case_code')).toBeNull();
      expect(urlObj.searchParams.get('code')).toBeNull();
      expect(urlObj.search).not.toContain(testCaseCode);

      // Assertion B: No accidental Authorization header on anonymous requests
      expect(req.headers['authorization']).toBeUndefined();
      expect(req.headers['Authorization']).toBeUndefined();

      // Assertion C: For header-authenticated endpoints, verify case code is present ONLY in X-Case-Code header
      if (
        req.url.endsWith('/messages') ||
        req.url.includes('/messages?') ||
        req.url.endsWith('/notifications') ||
        req.url.endsWith('/verification') ||
        req.url.endsWith('/withdraw')
      ) {
        expect(req.headers['X-Case-Code']).toBe(testCaseCode);
      }
    }

    // =========================================================================
    // STRICT ADVERSARIAL AUDIT OF BROWSER STORAGE & DOM
    // =========================================================================
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe('');
    expect(window.location.search).toBe('');
    expect(window.location.pathname).toBe('/');
  });
});
