import React, { useState, useEffect } from 'react';
import { Activity, ShieldCheck, Check, Search, FileCheck } from 'lucide-react';
import { getLatestSTH, getInclusionProof, getLatestCanary, getCanaryHistory } from '../api/transparency';
import { Alert } from '../components/Alert';
import type { SignedTreeHeadResponse, InclusionProofResponse, WarrantCanaryResponse } from '../types';

export const TransparencyPage: React.FC = () => {
  const [sth, setSth] = useState<SignedTreeHeadResponse | null>(null);
  const [canary, setCanary] = useState<WarrantCanaryResponse | null>(null);
  const [history, setHistory] = useState<WarrantCanaryResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Verifier input
  const [verifyLeafIndex, setVerifyLeafIndex] = useState('');
  const [verifyTreeSize, setVerifyTreeSize] = useState('');
  const [proofResult, setProofResult] = useState<InclusionProofResponse | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [sthRes, canaryRes, historyRes] = await Promise.all([
          getLatestSTH().catch(() => null),
          getLatestCanary().catch(() => null),
          getCanaryHistory().catch(() => []),
        ]);
        if (sthRes) setSth(sthRes);
        if (canaryRes) setCanary(canaryRes);
        if (historyRes) setHistory(historyRes);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load transparency telemetry.');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleVerifyInclusion = async (e: React.FormEvent) => {
    e.preventDefault();
    const lIndex = parseInt(verifyLeafIndex, 10);
    const tSize = parseInt(verifyTreeSize, 10);
    if (isNaN(lIndex) || isNaN(tSize)) {
      setVerifyError('Please enter valid numeric leaf index and tree size.');
      return;
    }

    setVerifying(true);
    setVerifyError(null);
    setProofResult(null);

    try {
      const res = await getInclusionProof(lIndex, tSize);
      setProofResult(res);
    } catch (err: unknown) {
      setVerifyError(err instanceof Error ? err.message : 'Inclusion proof could not be verified.');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
          Merkle Transparency & Warrant Canary Hub
        </h1>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.4rem', fontSize: '0.95rem' }}>
          Cryptographic commitments, public signed tree heads (RFC 6962), and tamper-evident warrant canary declarations.
        </p>
      </div>

      {error && <Alert type="danger">{error}</Alert>}

      <div className="grid-2">
        {/* Left: Merkle Signed Tree Head */}
        <div>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Append-Only Merkle Tree (RFC 6962)</span>
              <Activity size={18} color="#38bdf8" />
            </div>

            {loading ? (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.875rem' }}>Loading log telemetry...</div>
            ) : sth ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Committed Tree Size:</span>
                  <span className="mono" style={{ fontWeight: 700, color: '#38bdf8' }}>{sth.tree_size} leaves</span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>Root Hash (SHA-256):</span>
                  <div className="mono" style={{ background: '#0a0f18', padding: '0.5rem', borderRadius: 4, wordBreak: 'break-all', fontSize: '0.75rem', color: '#10b981' }}>
                    {sth.root_hash}
                  </div>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>STH Signature (Ed25519):</span>
                  <div className="mono" style={{ background: '#0a0f18', padding: '0.5rem', borderRadius: 4, wordBreak: 'break-all', fontSize: '0.75rem', color: 'var(--text-main)' }}>
                    {sth.signature}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                  <span>Signing Key: <span className="mono">{sth.signing_key_id}</span></span>
                  <span>Issued: {new Date(sth.timestamp).toLocaleString()}</span>
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.875rem' }}>No public Tree Head published yet.</div>
            )}
          </div>

          {/* Interactive Inclusion Proof Verifier */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Inclusion Proof Verifier</span>
              <FileCheck size={18} color="#10b981" />
            </div>

            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
              Verify that an anonymous report receipt is immutably committed within the global Merkle tree without revealing report contents.
            </p>

            {verifyError && <Alert type="danger">{verifyError}</Alert>}

            <form onSubmit={handleVerifyInclusion}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                    Leaf Index
                  </label>
                  <input
                    type="number"
                    placeholder="e.g. 0"
                    value={verifyLeafIndex}
                    onChange={(e) => setVerifyLeafIndex(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                    Tree Size
                  </label>
                  <input
                    type="number"
                    placeholder="e.g. 1"
                    value={verifyTreeSize}
                    onChange={(e) => setVerifyTreeSize(e.target.value)}
                    required
                  />
                </div>
              </div>

              <button type="submit" disabled={verifying} className="btn btn-secondary" style={{ width: '100%', fontSize: '0.85rem' }}>
                <Search size={14} />
                {verifying ? 'Calculating Audit Path...' : 'Verify Cryptographic Inclusion'}
              </button>
            </form>

            {proofResult && (
              <div style={{ background: '#0a0f18', border: '1px solid #1f2d42', borderRadius: 6, padding: '0.85rem', marginTop: '1rem', fontSize: '0.8rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#10b981', fontWeight: 600, marginBottom: '0.5rem' }}>
                  <Check size={15} />
                  Mathematically Verified Inclusion
                </div>
                <div>Leaf Hash: <span className="mono" style={{ color: '#38bdf8' }}>{proofResult.leaf_hash.slice(0, 24)}...</span></div>
                <div>Audit Path Length: <span className="mono">{proofResult.audit_path.length} sibling hashes</span></div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.35rem' }}>
                  Audit Path: [{proofResult.audit_path.map((h) => h.slice(0, 8)).join(', ')}]
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Warrant Canary */}
        <div>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Warrant Canary & Anti-Coercion</span>
              <ShieldCheck size={18} color={canary?.is_active ? '#10b981' : '#f59e0b'} />
            </div>

            {canary ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <span className={`badge ${canary.is_active ? 'badge-resolved' : 'badge-under_review'}`}>
                    {canary.status}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Serial #{canary.statement_serial}
                  </span>
                </div>

                <div
                  style={{
                    background: '#090e17',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    padding: '1rem',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    lineHeight: 1.6,
                    color: 'var(--text-main)',
                    whiteSpace: 'pre-wrap',
                    marginBottom: '1rem',
                  }}
                >
                  {canary.statement_text}
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                  <div>Valid Until: <span className="mono" style={{ color: '#f8fafc' }}>{new Date(canary.valid_until).toUTCString()}</span></div>
                  <div>Signing Key: <span className="mono">{canary.signing_key_id}</span></div>
                  <div>Signature: <span className="mono" style={{ color: '#38bdf8' }}>{canary.signature.slice(0, 32)}...</span></div>
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.875rem' }}>No warrant canary currently published.</div>
            )}
          </div>

          {/* Historical Canaries Table */}
          {history.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">Canary Historical Archive</span>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Serial</th>
                    <th>Issued At</th>
                    <th>Valid Until</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((c) => (
                    <tr key={c.statement_serial}>
                      <td className="mono">#{c.statement_serial}</td>
                      <td>{new Date(c.issued_at).toLocaleDateString()}</td>
                      <td>{new Date(c.valid_until).toLocaleDateString()}</td>
                      <td>
                        <span className={`badge ${c.is_active ? 'badge-resolved' : 'badge-dismissed'}`}>
                          {c.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
