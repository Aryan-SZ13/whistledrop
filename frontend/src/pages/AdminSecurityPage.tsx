import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  AlertTriangle,
  Lock,
  Unlock,
  CheckCircle,
  Plus,
  Trash2,
} from 'lucide-react';
import {
  listQuorumProposals,
  approveQuorum,
  rejectQuorum,
  listWebhooks,
  createWebhook,
  deleteWebhook,
  getSecurityState,
  adminCheckIn,
  emergencySeal,
  emergencyUnseal,
} from '../api/moderator';
import { Alert } from '../components/Alert';
import { useAuth } from '../context/AuthContext';
import type {
  QuorumProposal,
  WebhookEndpointItem,
  SecurityStateResponse,
} from '../types';

export const AdminSecurityPage: React.FC = () => {
  const { token } = useAuth();

  const [securityState, setSecurityState] = useState<SecurityStateResponse | null>(null);
  const [proposals, setProposals] = useState<QuorumProposal[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookEndpointItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Dead-man switch check-in modal
  const [showCheckInModal, setShowCheckInModal] = useState(false);
  const [checkInTotp, setCheckInTotp] = useState('');
  const [checkingIn, setCheckingIn] = useState(false);

  // Emergency Seal modal
  const [showSealModal, setShowSealModal] = useState(false);
  const [sealReason, setSealReason] = useState('');
  const [sealing, setSealing] = useState(false);

  // Quorum Approval modal
  const [approvingProposalId, setApprovingProposalId] = useState<string | null>(null);
  const [approvalTotp, setApprovalTotp] = useState('');
  const [approving, setApproving] = useState(false);

  // New Webhook modal
  const [showWebhookModal, setShowWebhookModal] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookDesc, setWebhookDesc] = useState('');
  const [creatingWebhook, setCreatingWebhook] = useState(false);

  const fetchSecurityData = useCallback(async () => {
    if (!token) return;
    setError(null);
    try {
      const [secRes, qRes, whRes] = await Promise.all([
        getSecurityState(token).catch(() => null),
        listQuorumProposals(token).catch(() => []),
        listWebhooks(token).catch(() => []),
      ]);
      if (secRes) setSecurityState(secRes);
      setProposals(qRes || []);
      setWebhooks(whRes || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve administrative state.');
    }
  }, [token]);

  useEffect(() => {
    fetchSecurityData();
  }, [fetchSecurityData]);

  const handleAdminCheckIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !checkInTotp.trim()) return;

    setCheckingIn(true);
    try {
      const res = await adminCheckIn(token, checkInTotp.trim());
      setSuccess(`Dead-man switch extended! Next check-in due: ${new Date(res.next_due_at).toLocaleString()}`);
      setShowCheckInModal(false);
      setCheckInTotp('');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Admin check-in failed (invalid TOTP).');
    } finally {
      setCheckingIn(false);
    }
  };

  const handleEmergencySeal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !sealReason.trim()) return;

    setSealing(true);
    try {
      const res = await emergencySeal(token, sealReason.trim());
      setSuccess(`Emergency seal engaged at ${new Date(res.sealed_at).toLocaleString()}. Operator plaintext access is locked.`);
      setShowSealModal(false);
      setSealReason('');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Emergency seal engagement failed.');
    } finally {
      setSealing(false);
    }
  };

  const handleEmergencyUnseal = async () => {
    if (!token) return;
    if (!window.confirm('Are you sure you want to disengage emergency access sealing?')) return;

    try {
      await emergencyUnseal(token);
      setSuccess('Emergency seal disengaged. Standard operator access restored.');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Emergency unseal failed.');
    }
  };

  const handleApproveProposal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !approvingProposalId || !approvalTotp.trim()) return;

    setApproving(true);
    try {
      await approveQuorum(token, approvingProposalId, approvalTotp.trim());
      setSuccess('Quorum proposal approved and executed with live MFA proof.');
      setApprovingProposalId(null);
      setApprovalTotp('');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Approval failed (Four-eyes violation or invalid TOTP).');
    } finally {
      setApproving(false);
    }
  };

  const handleRejectProposal = async (proposalId: string) => {
    if (!token) return;
    const reason = window.prompt('Provide rejection reason:');
    if (!reason) return;

    try {
      await rejectQuorum(token, proposalId, reason);
      setSuccess('Proposal rejected.');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Rejection failed.');
    }
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !webhookUrl.trim()) return;

    setCreatingWebhook(true);
    try {
      const res = await createWebhook(token, {
        url: webhookUrl.trim(),
        description: webhookDesc.trim() || undefined,
        subscribed_events: ['report.created', 'report.status_changed'],
      });
      setSuccess(`Webhook registered with ID ${res.endpoint_id}. Shared secret generated.`);
      setShowWebhookModal(false);
      setWebhookUrl('');
      setWebhookDesc('');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Webhook creation failed (SSRF check failed).');
    } finally {
      setCreatingWebhook(false);
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    if (!token || !window.confirm('Delete this webhook endpoint?')) return;
    try {
      await deleteWebhook(token, id);
      setSuccess('Webhook endpoint deleted.');
      fetchSecurityData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Webhook deletion failed.');
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
          Security Administration & Quorum Governance
        </h1>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.2rem', fontSize: '0.85rem' }}>
          Dual-control "Four-Eyes" principle, operational dead-man switch, and emergency access sealing
        </p>
      </div>

      {error && <Alert type="danger">{error}</Alert>}
      {success && <Alert type="success">{success}</Alert>}

      {/* Emergency Seal & Dead-Man Switch Card */}
      {securityState && (
        <div className="card" style={{ border: securityState.is_sealed ? '1px solid #ef4444' : '1px solid var(--border)' }}>
          <div className="card-header">
            <span className="card-title">System Security & Access Boundary</span>
            {securityState.is_sealed ? <Lock size={20} color="#ef4444" /> : <Unlock size={20} color="#10b981" />}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
            <div style={{ background: '#0e1624', padding: '0.85rem', borderRadius: 6 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Emergency Access Seal</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, color: securityState.is_sealed ? '#ef4444' : '#10b981', marginTop: '0.2rem' }}>
                {securityState.is_sealed ? 'ENGAGED (LOCKED)' : 'DISENGAGED (NORMAL)'}
              </div>
              {securityState.seal_reason && (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                  Reason: {securityState.seal_reason}
                </div>
              )}
            </div>

            <div style={{ background: '#0e1624', padding: '0.85rem', borderRadius: 6 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Dead-Man Switch Due</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.2rem' }}>
                {securityState.dead_man_due_at ? new Date(securityState.dead_man_due_at).toLocaleDateString() : 'Active'}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                Requires regular admin TOTP check-in
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button onClick={() => setShowCheckInModal(true)} className="btn btn-secondary">
              <CheckCircle size={15} color="#10b981" />
              Admin Dead-Man Check-In
            </button>

            {securityState.is_sealed ? (
              <button onClick={handleEmergencyUnseal} className="btn btn-primary">
                <Unlock size={15} />
                Disengage Emergency Seal
              </button>
            ) : (
              <button onClick={() => setShowSealModal(true)} className="btn btn-danger">
                <Lock size={15} />
                Engage Emergency Access Seal
              </button>
            )}
          </div>
        </div>
      )}

      {/* Quorum Governance Proposals */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Dual-Control Quorum Proposals ("Four-Eyes" Principle)</span>
          <Users size={18} color="#38bdf8" />
        </div>

        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
          Critical administrative actions (retention sweeps, case reopen, webhook deletion) require two distinct administrators to propose and approve with fresh MFA verification.
        </p>

        {proposals.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No active quorum proposals.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Action Type</th>
                <th>Target Entity</th>
                <th>Status</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {proposals.map((p) => (
                <tr key={p.id}>
                  <td style={{ fontWeight: 600 }}>{p.action_type}</td>
                  <td>{p.target_entity_type} {p.target_entity_id ? `(${p.target_entity_id.slice(0, 8)}...)` : ''}</td>
                  <td>
                    <span className={`badge ${p.status === 'APPROVED' ? 'badge-resolved' : p.status === 'PENDING' ? 'badge-under_review' : 'badge-dismissed'}`}>
                      {p.status}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {new Date(p.expires_at).toLocaleString()}
                  </td>
                  <td>
                    {p.status === 'PENDING' && (
                      <div style={{ display: 'flex', gap: '0.4rem' }}>
                        <button
                          onClick={() => setApprovingProposalId(p.id)}
                          className="btn btn-primary"
                          style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                        >
                          Approve (MFA)
                        </button>
                        <button
                          onClick={() => handleRejectProposal(p.id)}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                        >
                          Reject
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Outbound Webhooks Management */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Transactional Outbox Webhook Endpoints</span>
          <button onClick={() => setShowWebhookModal(true)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
            <Plus size={14} />
            Register Endpoint
          </button>
        </div>

        {webhooks.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No webhook endpoints registered.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Endpoint URL</th>
                <th>Events</th>
                <th>Status</th>
                <th>Failures</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map((wh) => (
                <tr key={wh.id}>
                  <td className="mono" style={{ fontSize: '0.8rem' }}>{wh.url}</td>
                  <td style={{ fontSize: '0.8rem' }}>{wh.subscribed_events.join(', ')}</td>
                  <td>
                    <span className={`badge ${wh.is_active ? 'badge-resolved' : 'badge-dismissed'}`}>
                      {wh.is_active ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </td>
                  <td style={{ color: wh.failure_count > 0 ? '#ef4444' : 'var(--text-main)' }}>
                    {wh.failure_count}
                  </td>
                  <td>
                    <button
                      onClick={() => handleDeleteWebhook(wh.id)}
                      className="btn btn-danger"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                    >
                      <Trash2 size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Dead-Man Switch Check-In Modal */}
      {showCheckInModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.75rem' }}>Admin Dead-Man Check-In</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
              Confirm your operational availability by providing your live 6-digit TOTP code.
            </p>
            <form onSubmit={handleAdminCheckIn}>
              <input
                type="text"
                className="mono"
                placeholder="123456"
                value={checkInTotp}
                onChange={(e) => setCheckInTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                maxLength={6}
                required
                style={{ textAlign: 'center', fontSize: '1.25rem', letterSpacing: '0.2em', marginBottom: '1.25rem' }}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button type="button" onClick={() => setShowCheckInModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={checkingIn || checkInTotp.length < 6} className="btn btn-primary">
                  {checkingIn ? 'Verifying...' : 'Confirm Check-In'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Emergency Seal Modal */}
      {showSealModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ef4444', marginBottom: '0.5rem' }}>
              <AlertTriangle size={22} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Engage Emergency Access Seal</h3>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
              Engaging the emergency seal blocks all operator plaintext case views, message inspections, and exports.
              Whistleblower intake and anonymous tracking remain active.
            </p>
            <form onSubmit={handleEmergencySeal}>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                  Mandatory Sealing Reason *
                </label>
                <textarea
                  rows={3}
                  placeholder="e.g. Physical infrastructure inspection, suspected operator host compromise..."
                  value={sealReason}
                  onChange={(e) => setSealReason(e.target.value)}
                  required
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button type="button" onClick={() => setShowSealModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={sealing || !sealReason.trim()} className="btn btn-danger">
                  {sealing ? 'Sealing...' : 'Engage Emergency Seal'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Quorum Approval Modal */}
      {approvingProposalId && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.75rem' }}>Approve Quorum Proposal</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
              Approval requires fresh live TOTP MFA proof. You cannot approve your own proposal (Four-Eyes enforcement).
            </p>
            <form onSubmit={handleApproveProposal}>
              <input
                type="text"
                className="mono"
                placeholder="123456"
                value={approvalTotp}
                onChange={(e) => setApprovalTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                maxLength={6}
                required
                style={{ textAlign: 'center', fontSize: '1.25rem', letterSpacing: '0.2em', marginBottom: '1.25rem' }}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button type="button" onClick={() => { setApprovingProposalId(null); setApprovalTotp(''); }} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={approving || approvalTotp.length < 6} className="btn btn-primary">
                  {approving ? 'Verifying & Executing...' : 'Confirm Approval'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Webhook Registration Modal */}
      {showWebhookModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.75rem' }}>Register Signed Webhook</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
              Deliver outbound events securely. Destinations are strictly checked against SSRF and private networks.
            </p>
            <form onSubmit={handleCreateWebhook}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                  Destination URL (HTTPS required in production) *
                </label>
                <input
                  type="url"
                  placeholder="https://audit.example.org/webhook"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  required
                />
              </div>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                  Description / Service Name
                </label>
                <input
                  type="text"
                  placeholder="External Legal SIEM / Outbox Consumer"
                  value={webhookDesc}
                  onChange={(e) => setWebhookDesc(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button type="button" onClick={() => setShowWebhookModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={creatingWebhook || !webhookUrl.trim()} className="btn btn-primary">
                  {creatingWebhook ? 'Validating SSRF...' : 'Register Webhook'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
