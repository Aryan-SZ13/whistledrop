import React, { useState } from 'react';
import { AlertTriangle, ShieldCheck, ChevronDown, ChevronUp, Info, Eye } from 'lucide-react';
import type { PreflightScanResult } from '../utils/privacyPreflight';

interface PrivacyPreflightBannerProps {
  scanResult: PreflightScanResult;
  onFocusDescription: () => void;
  acknowledged: boolean;
  onToggleAcknowledge: (acknowledged: boolean) => void;
}

export const PrivacyPreflightBanner: React.FC<PrivacyPreflightBannerProps> = ({
  scanResult,
  onFocusDescription,
  acknowledged,
  onToggleAcknowledge,
}) => {
  const [expanded, setExpanded] = useState(true);

  if (!scanResult.hasWarnings) {
    return null;
  }

  const criticalCount = scanResult.criticalCount;
  const totalCount = scanResult.findings.length;

  return (
    <div
      role="region"
      aria-label="Privacy Preflight Advisory"
      aria-live="polite"
      style={{
        background: acknowledged ? '#0e1726' : '#1e140a',
        border: `1px solid ${acknowledged ? '#1e3a5f' : '#b45309'}`,
        borderRadius: '8px',
        padding: '1rem 1.25rem',
        marginBottom: '1.25rem',
        transition: 'all 0.2s ease',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
          {acknowledged ? (
            <ShieldCheck size={20} color="#38bdf8" style={{ marginTop: '0.15rem', flexShrink: 0 }} />
          ) : (
            <AlertTriangle size={20} color="#f59e0b" style={{ marginTop: '0.15rem', flexShrink: 0 }} />
          )}
          <div>
            <h4
              style={{
                fontSize: '0.95rem',
                fontWeight: 700,
                color: acknowledged ? '#38bdf8' : '#fef3c7',
                margin: 0,
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              Privacy Preflight:{' '}
              {totalCount === 1 ? '1 Potential Identifier Detected' : `${totalCount} Potential Identifiers Detected`}
              {criticalCount > 0 && !acknowledged && (
                <span
                  style={{
                    fontSize: '0.7rem',
                    background: '#78350f',
                    color: '#fef3c7',
                    padding: '0.15rem 0.45rem',
                    borderRadius: 4,
                  }}
                >
                  {criticalCount} Critical
                </span>
              )}
            </h4>
            <p style={{ fontSize: '0.82rem', color: '#cbd5e1', margin: '0.3rem 0 0' }}>
              {acknowledged
                ? 'You have reviewed the detected snippets and marked them as relevant evidence. You may now submit.'
                : 'Before submitting, check whether the highlighted items are your personal details or evidence about the incident.'}
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          style={{
            background: 'transparent',
            border: 'none',
            color: '#94a3b8',
            cursor: 'pointer',
            padding: '0.2rem',
            display: 'flex',
            alignItems: 'center',
          }}
          aria-expanded={expanded}
          aria-label={expanded ? 'Collapse findings' : 'Expand findings'}
        >
          {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </button>
      </div>

      {expanded && (
        <div style={{ marginTop: '1rem', borderTop: '1px solid rgba(255, 255, 255, 0.1)', paddingTop: '0.75rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {scanResult.findings.map((f) => (
              <div
                key={f.id}
                style={{
                  background: '#090d16',
                  border: '1px solid #1e293b',
                  borderRadius: 6,
                  padding: '0.65rem 0.85rem',
                  fontSize: '0.82rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                  <span style={{ fontWeight: 600, color: f.severity === 'CRITICAL' ? '#f59e0b' : '#38bdf8' }}>
                    {f.label}
                  </span>
                  <span
                    className="mono"
                    style={{
                      background: '#1e293b',
                      color: '#f8fafc',
                      padding: '0.15rem 0.4rem',
                      borderRadius: 3,
                      fontSize: '0.75rem',
                      maxWidth: '220px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    "{f.snippet}"
                  </span>
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{f.explanation}</div>
                <div style={{ color: '#64748b', fontSize: '0.75rem', marginTop: '0.2rem', fontStyle: 'italic' }}>
                  Tip: {f.recommendation}
                </div>
              </div>
            ))}
          </div>

          <div
            style={{
              marginTop: '1rem',
              display: 'flex',
              flexWrap: 'wrap',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.72rem', color: '#64748b' }}>
              <Info size={13} />
              <span>
                <strong>100% In-Browser Scan:</strong> Draft text is evaluated strictly in your browser and has NOT been sent to any server.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <button
                type="button"
                onClick={onFocusDescription}
                className="btn btn-secondary"
                style={{ fontSize: '0.78rem', padding: '0.35rem 0.65rem' }}
              >
                <Eye size={13} />
                Edit Draft
              </button>
              <label
                htmlFor="preflight-ack-checkbox"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  fontSize: '0.8rem',
                  color: acknowledged ? '#38bdf8' : '#f59e0b',
                  cursor: 'pointer',
                  fontWeight: 600,
                  userSelect: 'none',
                }}
              >
                <input
                  id="preflight-ack-checkbox"
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => onToggleAcknowledge(e.target.checked)}
                  aria-label="Confirm detected snippets are incident evidence and allow submission"
                  style={{ accentColor: '#38bdf8', cursor: 'pointer' }}
                />
                This is incident evidence (allow submission)
              </label>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
