/**
 * WhistleDrop Privacy Preflight Engine
 *
 * Client-Side In-Browser Detector for Potentially Identifying Details in Draft Reports.
 *
 * PRIVACY GUARANTEES:
 * 1. 100% In-Browser Execution: Zero network requests are initiated.
 * 2. Zero Persistence: Scanned drafts and detected findings are never logged or stored.
 * 3. Advisory Only: Detection never automatically modifies, redacts, or blocks submissions.
 * 4. Whistleblower Agency: Informants review findings to distinguish their own identity
 *    from factual evidence about perpetrators.
 */

export type PreflightFindingType =
  | 'EMAIL'
  | 'PHONE'
  | 'IP_ADDRESS'
  | 'TRACKING_URL'
  | 'STRUCTURED_ID'
  | 'SELF_IDENTIFIER';

export interface PreflightFinding {
  id: string;
  type: PreflightFindingType;
  label: string;
  snippet: string;
  startIndex: number;
  endIndex: number;
  explanation: string;
  severity: 'CRITICAL' | 'WARNING';
  recommendation: string;
}

export interface PreflightScanResult {
  findings: PreflightFinding[];
  hasWarnings: boolean;
  criticalCount: number;
  scanDurationMs: number;
  scannedLength: number;
}

// Bounded, ReDoS-safe patterns for structured PII identifiers
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// Matches phone numbers with explicit international prefixes, area codes, or domestic 3-group separators
// ReDoS-safe and specifically excludes plain year ranges (e.g. 2020-2024), dates, and order numbers
const PHONE_REGEX = /(?:(?:\+\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)[-.\s]?|\b\d{3}[-.\s])\d{3}[-.\s]?\d{4}\b|\+\d{1,3}[-.\s]?(?:\d{2,4}[-.\s]?){2,3}\d{2,4}\b|\b0\d{2,4}[-.\s]\d{3,4}[-.\s]?\d{3,4}\b)/g;

// Matches IPv4 addresses (e.g. 192.168.1.1, 10.0.4.15)
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;

// Matches URLs containing query parameters that often carry session tokens, user IDs, or tracking tags
const TRACKING_URL_REGEX = /https?:\/\/[^\s/$.?#].[^\s]*(?:[?&](?:token|auth|session|user|email|uid|utm_[a-z]+|id|api_key|code)=)[^\s.,!?)]*/gi;

// Matches internal corporate domains (e.g. intranet.corp, service.internal)
const INTERNAL_HOST_REGEX = /(?:https?:\/\/|(?<!@)\b)[A-Za-z0-9.-]+\.(?:internal|corp|local|intranet|lan)\b(?:\/[^\s.,!?)]*)?/gi;

// Matches structured employee badges, IDs, or SSN format (must contain digits to prevent matching words like "Employee")
const EMPLOYEE_ID_REGEX = /\b(?:EMP(?:LOYEE)?|BADGE|STAFF)[-_:#\s]*[0-9A-Za-z]*[0-9]+[0-9A-Za-z]*\b/gi;
const SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;

// Matches first-person self-disclosure patterns (e.g. "my name is Alice", "contact me at ...")
const SELF_DISCLOSURE_REGEX = /\b(?:my name is|i am the|contact me at|reach me at|my desk is|my direct line is)\s+([^\n,.]{2,40})/gi;

/**
 * Executes a deterministic, client-side privacy scan across the provided text.
 * Pure function with zero network, storage, or logging side effects.
 */
export function scanDraftText(text: string): PreflightScanResult {
  const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();

  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return {
      findings: [],
      hasWarnings: false,
      criticalCount: 0,
      scanDurationMs: 0,
      scannedLength: 0,
    };
  }

  const findings: PreflightFinding[] = [];
  const seenRanges = new Set<string>();

  // Reset lastIndex on global regexes to ensure thread/re-entrant safety
  EMAIL_REGEX.lastIndex = 0;
  PHONE_REGEX.lastIndex = 0;
  IPV4_REGEX.lastIndex = 0;
  TRACKING_URL_REGEX.lastIndex = 0;
  INTERNAL_HOST_REGEX.lastIndex = 0;
  EMPLOYEE_ID_REGEX.lastIndex = 0;
  SSN_REGEX.lastIndex = 0;
  SELF_DISCLOSURE_REGEX.lastIndex = 0;

  const addFinding = (
    type: PreflightFindingType,
    label: string,
    snippet: string,
    startIndex: number,
    endIndex: number,
    explanation: string,
    severity: 'CRITICAL' | 'WARNING',
    recommendation: string
  ) => {
    const key = `${startIndex}-${endIndex}-${type}`;
    if (seenRanges.has(key)) return;
    seenRanges.add(key);

    // Ignore sub-ranges already subsumed by an existing broader finding (e.g. host domain inside an email)
    for (const existing of findings) {
      if (startIndex >= existing.startIndex && endIndex <= existing.endIndex) {
        return;
      }
    }

    findings.push({
      id: `preflight-${findings.length + 1}`,
      type,
      label,
      snippet,
      startIndex,
      endIndex,
      explanation,
      severity,
      recommendation,
    });
  };

  // 1. Email addresses
  let match: RegExpExecArray | null;
  while ((match = EMAIL_REGEX.exec(text)) !== null) {
    addFinding(
      'EMAIL',
      'Email Address Detected',
      match[0],
      match.index,
      match.index + match[0].length,
      `Detected an email address ("${match[0]}"). If this is your personal or corporate work email, it will reveal your identity.`,
      'CRITICAL',
      'If this is your own contact address, remove it. If this is the email of the person you are reporting, you may keep it as evidence.'
    );
  }

  // 2. Phone numbers
  while ((match = PHONE_REGEX.exec(text)) !== null) {
    // Basic filter to avoid simple years like "2024" or short numbers
    const digitsOnly = match[0].replace(/\D/g, '');
    if (digitsOnly.length >= 7) {
      addFinding(
        'PHONE',
        'Phone Number Detected',
        match[0],
        match.index,
        match.index + match[0].length,
        `Detected what appears to be a phone number ("${match[0]}").`,
        'CRITICAL',
        'Ensure this is not your personal mobile or desk phone number before submitting.'
      );
    }
  }

  // 3. IP Addresses
  while ((match = IPV4_REGEX.exec(text)) !== null) {
    const ip = match[0];
    if (ip !== '0.0.0.0' && ip !== '127.0.0.1') {
      const prefix = text.slice(Math.max(0, match.index - 10), match.index).toLowerCase();
      // Exclude software version numbers like "1.2.3.4" or "Section 2.3.4.1"
      if (!/(?:v|version\s*|section\s*)$/i.test(prefix)) {
        const octets = ip.split('.').map(Number);
        const allSingleDigits = octets.every((o) => o < 10);
        if (!allSingleDigits || ip === '1.1.1.1' || ip === '8.8.8.8' || ip === '9.9.9.9') {
          addFinding(
            'IP_ADDRESS',
            'IP Address Detected',
            ip,
            match.index,
            match.index + ip.length,
            `Detected an IP address ("${ip}"). Internal IP addresses may pinpoint your subnet or physical office location.`,
            'WARNING',
            'Verify if this IP identifies your local machine or an external server involved in the incident.'
          );
        }
      }
    }
  }

  // 4. Tracking URLs & Internal Hosts
  while ((match = TRACKING_URL_REGEX.exec(text)) !== null) {
    addFinding(
      'TRACKING_URL',
      'URL with Tracking Parameters Detected',
      match[0],
      match.index,
      match.index + match[0].length,
      'This URL contains query parameters (e.g. token, session, user ID) that might link back to your authenticated browser session.',
      'CRITICAL',
      'Strip query parameters or session tokens from the link before submitting.'
    );
  }

  while ((match = INTERNAL_HOST_REGEX.exec(text)) !== null) {
    addFinding(
      'TRACKING_URL',
      'Internal Corporate Host Detected',
      match[0],
      match.index,
      match.index + match[0].length,
      `Detected a reference to an internal company domain ("${match[0]}").`,
      'WARNING',
      'Confirm whether naming internal infrastructure exposes your specific team or network access.'
    );
  }

  // 5. Structured Employee Badges & SSN
  while ((match = EMPLOYEE_ID_REGEX.exec(text)) !== null) {
    addFinding(
      'STRUCTURED_ID',
      'Employee or Badge ID Detected',
      match[0],
      match.index,
      match.index + match[0].length,
      `Detected what appears to be an employee badge or staff identifier ("${match[0]}").`,
      'CRITICAL',
      'If this is your own badge number, remove it. If it identifies the subject of investigation, you may retain it.'
    );
  }

  while ((match = SSN_REGEX.exec(text)) !== null) {
    addFinding(
      'STRUCTURED_ID',
      'Government / Social Security Number Format',
      match[0],
      match.index,
      match.index + match[0].length,
      'Detected a 9-digit SSN or national identification number pattern.',
      'CRITICAL',
      'Remove your personal identification number unless strictly necessary as incident evidence.'
    );
  }

  // 6. First-Person Self-Disclosure Phrases
  while ((match = SELF_DISCLOSURE_REGEX.exec(text)) !== null) {
    addFinding(
      'SELF_IDENTIFIER',
      'Self-Disclosure Phrase Detected',
      match[0],
      match.index,
      match.index + match[0].length,
      `Detected a phrase that may reveal personal details ("${match[0]}").`,
      'WARNING',
      'Consider rephrasing to maintain a neutral third-person perspective (e.g. "An employee in accounting noticed..." instead of "I am the senior accountant...").'
    );
  }

  // Sort findings in the exact order they appear in the narrative text
  findings.sort((a, b) => a.startIndex - b.startIndex || a.endIndex - b.endIndex);
  findings.forEach((f, idx) => {
    f.id = `preflight-${idx + 1}`;
  });

  const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const scanDurationMs = Math.round((endTime - startTime) * 100) / 100;
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;

  return {
    findings,
    hasWarnings: findings.length > 0,
    criticalCount,
    scanDurationMs,
    scannedLength: text.length,
  };
}
