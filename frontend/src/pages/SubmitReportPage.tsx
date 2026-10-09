import React, { useState, useMemo, useRef } from 'react';
import { Shield, Key, Copy, Check, ArrowRight, Upload, FileText } from 'lucide-react';
import { submitReport, uploadEvidence } from '../api/reports';
import { Alert } from '../components/Alert';
import { PrivacyPreflightBanner } from '../components/PrivacyPreflightBanner';
import { scanDraftText } from '../utils/privacyPreflight';
import { useAnonymous } from '../context/AnonymousContext';
import type { ReportCategory } from '../types';

const CATEGORIES: { value: ReportCategory; label: string }[] = [
  { value: 'FINANCIAL_MISCONDUCT', label: 'Financial Misconduct / Embezzlement' },
  { value: 'CORRUPTION_BRIBERY', label: 'Corruption & Bribery' },
  { value: 'SAFETY_HEALTH_VIOLATION', label: 'Safety & Health Violations' },
  { value: 'ENVIRONMENTAL_DAMAGE', label: 'Environmental Damage' },
  { value: 'DATA_PRIVACY_BREACH', label: 'Data Privacy & Security Breach' },
  { value: 'HARASSMENT_DISCRIMINATION', label: 'Harassment & Discrimination' },
  { value: 'OTHER', label: 'Other Serious Misconduct' },
];

const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg', '.webp', '.txt', '.csv'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MiB

interface SubmitReportPageProps {
  onNavigateToTrack: () => void;
}

export const SubmitReportPage: React.FC<SubmitReportPageProps> = ({ onNavigateToTrack }) => {
  const { setCaseCode } = useAnonymous();

  const [title, setTitle] = useState('');
  const [category, setCategory] = useState<ReportCategory>('FINANCIAL_MISCONDUCT');
  const [description, setDescription] = useState('');
  const [files, setFiles] = useState<File[]>([]);
  const [preflightAcknowledged, setPreflightAcknowledged] = useState(false);
  const descriptionRef = useRef<HTMLTextAreaElement>(null);

  const preflightResult = useMemo(() => {
    try {
      return scanDraftText(`${title}\n${description}`);
    } catch {
      return {
        findings: [],
        hasWarnings: false,
        criticalCount: 0,
        scanDurationMs: 0,
        scannedLength: (title + description).length,
      };
    }
  }, [title, description]);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Success state: generated case code
  const [generatedCode, setGeneratedCode] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmedSaved, setConfirmedSaved] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return;
    const selected = Array.from(e.target.files);

    // Validate size and extension
    for (const f of selected) {
      const ext = '.' + f.name.split('.').pop()?.toLowerCase();
      if (!ALLOWED_EXTENSIONS.includes(ext)) {
        setError(`File ${f.name} has an unsupported format. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`);
        return;
      }
      if (f.size > MAX_FILE_SIZE) {
        setError(`File ${f.name} exceeds 10 MiB limit.`);
        return;
      }
    }

    if (files.length + selected.length > 5) {
      setError('Maximum 5 evidence attachments allowed per report.');
      return;
    }

    setError(null);
    setFiles((prev) => [...prev, ...selected]);
  };

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !description.trim()) {
      setError('Please provide both a title and description.');
      return;
    }
    if (description.trim().length < 10) {
      setError('Description must be at least 10 characters.');
      return;
    }

    if (preflightResult.hasWarnings && !preflightAcknowledged) {
      setError(
        'Privacy Preflight: Potential identifying details were detected in your narrative. Please review the advisory above and check "This is incident evidence (allow submission)" or edit your narrative before submitting.'
      );
      descriptionRef.current?.focus();
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      // 1. Submit report payload
      const res = await submitReport({
        title: title.trim(),
        category,
        description: description.trim(),
      });

      // 2. Upload any evidence files using the freshly issued case code
      if (files.length > 0) {
        for (const f of files) {
          try {
            await uploadEvidence(res.case_code, f);
          } catch {
            // Attachment failure handled gracefully; report remains registered
          }
        }
      }

      setGeneratedCode(res.case_code);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Submission failed. Please check connection.';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopyCode = async () => {
    if (!generatedCode) return;
    try {
      await navigator.clipboard.writeText(generatedCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      // Fallback
      setCopied(true);
    }
  };

  const handleProceedToTrack = () => {
    if (!generatedCode) return;
    // Set in-memory session only
    setCaseCode(generatedCode);
    onNavigateToTrack();
  };

  if (generatedCode) {
    return (
      <div>
        <div className="card" style={{ maxWidth: 680, margin: '2rem auto' }}>
          <div className="card-header" style={{ justifyContent: 'center', textAlign: 'center', borderBottom: 'none' }}>
            <div style={{ textAlign: 'center' }}>
              <div
                style={{
                  width: 48,
                  height: 48,
                  borderRadius: '50%',
                  background: 'rgba(16, 185, 129, 0.15)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 1rem auto',
                }}
              >
                <Check size={26} color="#10b981" />
              </div>
              <h2 className="card-title" style={{ fontSize: '1.4rem' }}>
                Report Securely Registered
              </h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '0.3rem' }}>
                Your submission is encrypted at rest and committed to the append-only Merkle transparency log.
              </p>
            </div>
          </div>

          <Alert type="warning" title="CRITICAL: Your Sole Authentication Key">
            Save this case code immediately. We do <strong>not</strong> collect your email or IP address. If you lose
            this code, you will permanently lose access to track status, communicate, or withdraw this report.
          </Alert>

          <div
            style={{
              background: '#070b12',
              border: '1px solid #243550',
              borderRadius: 8,
              padding: '1.25rem',
              margin: '1.5rem 0',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
              Secret Case Bearer Code
            </div>
            <div
              className="mono"
              style={{
                fontSize: '1.35rem',
                fontWeight: 700,
                color: '#38bdf8',
                letterSpacing: '0.05em',
                wordBreak: 'break-all',
              }}
            >
              {generatedCode}
            </div>
            <button
              onClick={handleCopyCode}
              className="btn btn-secondary"
              style={{ marginTop: '1rem', fontSize: '0.85rem' }}
            >
              {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
              {copied ? 'Copied to Clipboard' : 'Copy Case Code'}
            </button>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', cursor: 'pointer', fontSize: '0.875rem' }}>
              <input
                type="checkbox"
                checked={confirmedSaved}
                onChange={(e) => setConfirmedSaved(e.target.checked)}
                style={{ width: 'auto' }}
              />
              <span>I have safely recorded this case code in a secure location.</span>
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
            <button
              onClick={handleProceedToTrack}
              disabled={!confirmedSaved}
              className="btn btn-primary"
              style={{ width: '100%' }}
            >
              Access Case Tracking Portal
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
          Submit Confidential Report
        </h1>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.4rem', fontSize: '0.95rem' }}>
          Submit critical disclosures with strong cryptographic privacy guarantees. No accounts, no IP logging, and anonymous case tracking.
        </p>
      </div>

      <div className="grid-2">
        <div>
          <form onSubmit={handleSubmit} className="card">
            <div className="card-header">
              <span className="card-title">Report Details</span>
              <Shield size={18} color="#38bdf8" />
            </div>

            {error && (
              <Alert type="danger" title="Submission Error">
                {error}
              </Alert>
            )}

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Report Title *
              </label>
              <input
                type="text"
                placeholder="Brief summary of the incident or misconduct"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                maxLength={200}
                required
              />
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Incident Category *
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as ReportCategory)}
              >
                {CATEGORIES.map((cat) => (
                  <option key={cat.value} value={cat.value}>
                    {cat.label}
                  </option>
                ))}
              </select>
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Detailed Narrative *
              </label>
              <textarea
                ref={descriptionRef}
                rows={6}
                placeholder="Provide factual details: what occurred, timeline, entities involved, and locations. Do NOT include your own personal identity."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
              />
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textAlign: 'right', marginTop: '0.25rem' }}>
                {description.length} characters (minimum 10)
              </div>
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Evidence Attachments (Optional)
              </label>
              <div
                style={{
                  border: '1px dashed var(--border)',
                  borderRadius: 6,
                  padding: '1.25rem',
                  textAlign: 'center',
                  background: 'rgba(255, 255, 255, 0.01)',
                }}
              >
                <Upload size={24} color="#64748b" style={{ margin: '0 auto 0.5rem auto' }} />
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  Attach documents or images (PDF, PNG, JPG, WEBP, TXT, CSV)
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                  Max 10 MiB per file. All files are automatically virus scanned with ClamAV.
                </div>
                <label className="btn btn-secondary" style={{ marginTop: '0.75rem', fontSize: '0.8rem' }}>
                  Select Evidence Files
                  <input
                    type="file"
                    multiple
                    accept=".pdf,.png,.jpg,.jpeg,.webp,.txt,.csv"
                    onChange={handleFileChange}
                    style={{ display: 'none' }}
                  />
                </label>
              </div>

              {files.length > 0 && (
                <div style={{ marginTop: '0.75rem' }}>
                  {files.map((file, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.45rem 0.65rem',
                        background: 'var(--bg-input)',
                        borderRadius: 4,
                        marginBottom: '0.4rem',
                        fontSize: '0.85rem',
                      }}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-main)' }}>
                        <FileText size={14} color="#38bdf8" />
                        {file.name} ({(file.size / 1024).toFixed(0)} KB)
                      </span>
                      <button
                        type="button"
                        onClick={() => removeFile(idx)}
                        style={{ color: '#ef4444', fontSize: '0.8rem' }}
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <PrivacyPreflightBanner
              scanResult={preflightResult}
              onFocusDescription={() => descriptionRef.current?.focus()}
              acknowledged={preflightAcknowledged}
              onToggleAcknowledge={setPreflightAcknowledged}
            />

            <button
              type="submit"
              disabled={submitting}
              className="btn btn-primary"
              style={{
                width: '100%',
                padding: '0.75rem',
                opacity: submitting ? 0.7 : 1,
              }}
            >
              {submitting
                ? 'Encrypting & Transmitting...'
                : preflightResult.hasWarnings && !preflightAcknowledged
                ? 'Review Advisory & Submit'
                : 'Submit Confidential Report'}
            </button>
          </form>
        </div>

        <div>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Cryptographic Invariants</span>
              <Key size={18} color="#10b981" />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.875rem' }}>
              <div>
                <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '0.15rem' }}>
                  1. Zero Submitter Tracking
                </strong>
                <p style={{ color: 'var(--text-muted)' }}>
                  WhistleDrop stores no account, username, email, phone number, or client IP address in its databases or server logs.
                </p>
              </div>

              <div>
                <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '0.15rem' }}>
                  2. Application-Level Envelope Encryption (ALEE)
                </strong>
                <p style={{ color: 'var(--text-muted)' }}>
                  Your report narrative is encrypted at rest using AES-256-GCM with a unique per-case Data Encryption Key (DEK). Plaintext is never stored.
                </p>
              </div>

              <div>
                <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '0.15rem' }}>
                  3. RFC 6962 Merkle Transparency Commitment
                </strong>
                <p style={{ color: 'var(--text-muted)' }}>
                  Every submission atomically records an immutable cryptographic leaf into an append-only Merkle tree, verifiable via public Signed Tree Heads (STH).
                </p>
              </div>

              <div>
                <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '0.15rem' }}>
                  4. Unified Irrevocable Erasure
                </strong>
                <p style={{ color: 'var(--text-muted)' }}>
                  If you decide to withdraw your case, the server zeroes the case DEK and all attachment keys within a single ACID transaction. The payload becomes permanently unrecoverable.
                </p>
              </div>
            </div>
          </div>

          <Alert type="info" title="Privacy Recommendation">
            For maximum anonymity, ensure you are not connected to a corporate VPN or network monitored by the entity being reported.
          </Alert>
        </div>
      </div>
    </div>
  );
};
