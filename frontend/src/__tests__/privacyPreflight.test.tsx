import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { scanDraftText } from '../utils/privacyPreflight';
import { PrivacyPreflightBanner } from '../components/PrivacyPreflightBanner';

describe('Privacy Preflight Engine & Component Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('scanDraftText Deterministic Engine — Baseline & Positive Cases', () => {
    it('returns empty findings for clean narratives without personal identifiers', () => {
      const cleanDraft =
        'On Monday afternoon, the financial division altered the quarterly accounting records. Multiple invoices were re-routed through offshore shell holding accounts.';
      const res = scanDraftText(cleanDraft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
      expect(res.criticalCount).toBe(0);
      expect(res.scannedLength).toBe(cleanDraft.length);
    });

    it('returns empty findings for empty or whitespace-only drafts', () => {
      expect(scanDraftText('').hasWarnings).toBe(false);
      expect(scanDraftText('   \n  \t  ').hasWarnings).toBe(false);
    });

    it('detects email addresses and marks them as CRITICAL', () => {
      const draft = 'The whistleblower was informed by alice.smith@internal.company.com about the fraud.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(true);
      const emailFinding = res.findings.find((f) => f.type === 'EMAIL');
      expect(emailFinding).toBeDefined();
      expect(emailFinding?.snippet).toBe('alice.smith@internal.company.com');
      expect(emailFinding?.severity).toBe('CRITICAL');
      expect(res.criticalCount).toBeGreaterThanOrEqual(1);
    });

    it('detects international and domestic phone numbers in standard formats', () => {
      const draft =
        'Call me at +1 555-234-5678 or UK office at +44 20 7946 0991 or direct (555) 987-6543 to verify.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(true);
      const phoneFindings = res.findings.filter((f) => f.type === 'PHONE');
      expect(phoneFindings.length).toBe(3);
      expect(phoneFindings.some((f) => f.snippet.includes('+44 20 7946 0991'))).toBe(true);
      expect(phoneFindings.some((f) => f.snippet.includes('+1 555-234-5678'))).toBe(true);
      expect(phoneFindings.some((f) => f.snippet.includes('(555) 987-6543'))).toBe(true);
    });

    it('detects IP addresses while ignoring loopback (127.0.0.1) and all-zeros', () => {
      const draft = 'The rogue script connected from 10.14.88.23 and 192.168.1.105, but 127.0.0.1 is local.';
      const res = scanDraftText(draft);

      const ipFindings = res.findings.filter((f) => f.type === 'IP_ADDRESS');
      expect(ipFindings.length).toBe(2);
      expect(ipFindings.map((f) => f.snippet)).toContain('10.14.88.23');
      expect(ipFindings.map((f) => f.snippet)).toContain('192.168.1.105');
      expect(ipFindings.map((f) => f.snippet)).not.toContain('127.0.0.1');
    });

    it('detects tracking URLs with query parameters and internal corp domains', () => {
      const draft =
        'See evidence at https://internal-portal.corp/docs and https://external-drive.com/share?token=abc123secret&uid=9941.';
      const res = scanDraftText(draft);

      const urlFindings = res.findings.filter((f) => f.type === 'TRACKING_URL');
      expect(urlFindings.length).toBeGreaterThanOrEqual(2);
      expect(urlFindings.some((f) => f.snippet.includes('token='))).toBe(true);
    });

    it('detects employee badge IDs and Social Security Numbers', () => {
      const draft = 'Employee badge EMP-98231 was used at the secure vault door. Subject SSN was 123-45-6789.';
      const res = scanDraftText(draft);

      const idFindings = res.findings.filter((f) => f.type === 'STRUCTURED_ID');
      expect(idFindings.length).toBe(2);
      expect(idFindings.some((f) => f.snippet === 'EMP-98231')).toBe(true);
      expect(idFindings.some((f) => f.snippet === '123-45-6789')).toBe(true);
    });

    it('detects first-person self-disclosure phrases', () => {
      const draft = 'I am the senior lead accountant and my desk is on the 4th floor.';
      const res = scanDraftText(draft);

      const selfFindings = res.findings.filter((f) => f.type === 'SELF_IDENTIFIER');
      expect(selfFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('is completely idempotent and safe against regex state bleed across multiple scans', () => {
      const draft = 'Report with alice@example.com and phone +1 555-123-4567 repeated.';

      const scan1 = scanDraftText(draft);
      const scan2 = scanDraftText(draft);
      const scan3 = scanDraftText(draft);

      expect(scan1.findings.length).toBe(scan2.findings.length);
      expect(scan2.findings.length).toBe(scan3.findings.length);
      expect(scan1.findings.map((f) => f.snippet)).toEqual(scan2.findings.map((f) => f.snippet));
    });

    it('returns findings strictly ordered by position in narrative text', () => {
      const compound =
        'First see alice@corp.com, then call +1 555-111-2222, and check internal host 10.2.0.4.';
      const res = scanDraftText(compound);

      expect(res.findings.length).toBe(3);
      for (let i = 0; i < res.findings.length - 1; i++) {
        expect(res.findings[i].startIndex).toBeLessThanOrEqual(res.findings[i + 1].startIndex);
      }
      expect(res.findings[0].type).toBe('EMAIL');
      expect(res.findings[1].type).toBe('PHONE');
      expect(res.findings[2].type).toBe('IP_ADDRESS');
    });

    it('does not mutate or alter the original input draft text', () => {
      const input = 'Immutable draft text with confidential data.';
      const frozenInput = Object.freeze(input);
      const res = scanDraftText(frozenInput);

      expect(res.hasWarnings).toBe(false);
      expect(input).toBe('Immutable draft text with confidential data.');
    });
  });

  describe('scanDraftText Negative Edge Cases — Zero False Positives', () => {
    it('does not flag ordinary calendar years like 2024 and 2025 as phone numbers', () => {
      const draft = 'In 2024 and 2025, regular corporate audits occurred across all facilities.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
    });

    it('does not flag year ranges like 2020-2024 or 1999-2005 as phone numbers', () => {
      const draft = 'Between 2020-2024 the operational budget was reviewed annually. From 1999-2005 no issues arose.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
    });

    it('does not flag ISO calendar dates as phone numbers or identifiers', () => {
      const draft = 'The financial wire was dispatched on 2024-05-12 at 14:30:00.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
    });

    it('does not flag order IDs, invoices, or percentages', () => {
      const draft = 'Order #12345678 and Invoice 9876-5432 showed a 25% margin increase totaling $5,000,000.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
    });

    it('does not flag software version numbers or section headings as IP addresses', () => {
      const draft = 'Upgraded to software version 1.2.3.4 as outlined in Section 2.3.4.1 of the manual.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
    });

    it('does not flag common English dictionary words like "employee", "badge", or "staff" without IDs', () => {
      const draft = 'The manager discussed payroll with an employee who wore a badge and worked as staff.';
      const res = scanDraftText(draft);

      expect(res.hasWarnings).toBe(false);
      expect(res.findings).toHaveLength(0);
    });
  });

  describe('Privacy Preflight Guarantees (Zero Network & Zero Storage)', () => {
    it('executes without calling fetch or transmitting draft over the network', () => {
      const fetchMock = vi.fn();
      globalThis.fetch = fetchMock;

      const sensitiveText = 'My secret draft containing personal email whistleblower@secret.org and password xyz';
      const result = scanDraftText(sensitiveText);

      expect(result.hasWarnings).toBe(true);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('executes without writing to localStorage, sessionStorage, or document.cookie', () => {
      const sensitiveText = 'Draft text containing EMP-998822 and secret credentials';
      scanDraftText(sensitiveText);

      expect(localStorage.length).toBe(0);
      expect(sessionStorage.length).toBe(0);
      expect(document.cookie).toBe('');
    });
  });

  describe('PrivacyPreflightBanner Component Accessibility & Interaction', () => {
    it('renders null when there are no warnings', () => {
      const cleanResult = scanDraftText('Clean incident description without identifiers');
      const { container } = render(
        <PrivacyPreflightBanner
          scanResult={cleanResult}
          onFocusDescription={() => {}}
          acknowledged={false}
          onToggleAcknowledge={() => {}}
        />
      );

      expect(container.firstChild).toBeNull();
    });

    it('renders warning banner with accessible attributes, snippets, and handles acknowledgment', () => {
      const flaggedResult = scanDraftText('Contact me at insider@company.com');
      const toggleMock = vi.fn();
      const focusMock = vi.fn();

      const { rerender } = render(
        <PrivacyPreflightBanner
          scanResult={flaggedResult}
          onFocusDescription={focusMock}
          acknowledged={false}
          onToggleAcknowledge={toggleMock}
        />
      );

      // Verify accessible region and live announcement
      const region = screen.getByRole('region', { name: /Privacy Preflight Advisory/i });
      expect(region).toBeDefined();
      expect(region.getAttribute('aria-live')).toBe('polite');

      // Verify title and snippet displayed
      expect(screen.getByText(/Privacy Preflight:/i)).toBeDefined();
      expect(screen.getByText('"insider@company.com"')).toBeDefined();

      // Check edit draft button
      const editButton = screen.getByRole('button', { name: /Edit Draft/i });
      fireEvent.click(editButton);
      expect(focusMock).toHaveBeenCalledTimes(1);

      // Check accessible acknowledgment checkbox
      const checkbox = screen.getByLabelText(/Confirm detected snippets are incident evidence/i) as HTMLInputElement;
      expect(checkbox.checked).toBe(false);
      fireEvent.click(checkbox);
      expect(toggleMock).toHaveBeenCalledWith(true);

      // Re-render as acknowledged
      rerender(
        <PrivacyPreflightBanner
          scanResult={flaggedResult}
          onFocusDescription={focusMock}
          acknowledged={true}
          onToggleAcknowledge={toggleMock}
        />
      );

      expect(screen.getByText(/You have reviewed the detected snippets/i)).toBeDefined();
    });
  });
});
