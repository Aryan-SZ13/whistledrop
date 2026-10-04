import React, { useState, useEffect, useCallback } from 'react';
import { Eye, Send, Download, Trash2, RefreshCw, MessageSquare, ShieldCheck, Clock, AlertTriangle } from 'lucide-react';
import { getVerificationReceipt, withdrawReport } from '../api/reports';
import { listMessages, sendMessage, acknowledgeMessageRead, getNotifications } from '../api/messages';
import { Alert } from '../components/Alert';
import { StatusBadge } from '../components/Badge';
import { useAnonymous } from '../context/AnonymousContext';
import type {
  CaseMessagePublic,
  NotificationStatusResponse,
  VerificationReceiptResponse,
} from '../types';

export const TrackCasePage: React.FC = () => {
  const { caseCode, setCaseCode, clearCaseCode } = useAnonymous();

  const [inputCode, setInputCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Case tracking state (authenticated strictly via X-Case-Code header)
  const [notifications, setNotifications] = useState<NotificationStatusResponse | null>(null);
  const [messages, setMessages] = useState<CaseMessagePublic[]>([]);

  // New message state
  const [newMessage, setNewMessage] = useState('');
  const [sendingMessage, setSendingMessage] = useState(false);

  // Receipt state
  const [receipt, setReceipt] = useState<VerificationReceiptResponse | null>(null);
  const [loadingReceipt, setLoadingReceipt] = useState(false);

  // Withdrawal state
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  const [withdrawing, setWithdrawing] = useState(false);
  const [withdrawnMessage, setWithdrawnMessage] = useState<string | null>(null);

  const fetchCaseDetails = useCallback(async (code: string) => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch authoritative case status & version via X-Case-Code header
      const notifRes = await getNotifications(code);
      setNotifications(notifRes);

      // 2. Fetch two-way communications via X-Case-Code header
      try {
        const msgRes = await listMessages(code);
        setMessages(msgRes.items || []);
      } catch {
        // Message channel empty or unavailable
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not locate report or invalid case code.';
      setError(msg);
      setNotifications(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (caseCode) {
      fetchCaseDetails(caseCode);
    }
  }, [caseCode, fetchCaseDetails]);

  const handleManualLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputCode.trim()) return;
    setCaseCode(inputCode.trim());
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseCode || !newMessage.trim() || sendingMessage) return;

    setSendingMessage(true);
    try {
      const sent = await sendMessage(caseCode, newMessage.trim());
      setMessages((prev) => [...prev, sent]);
      setNewMessage('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to send message.';
      alert(msg);
    } finally {
      setSendingMessage(false);
    }
  };

  const handleFetchReceipt = async () => {
    if (!caseCode) return;
    setLoadingReceipt(true);
    try {
      const res = await getVerificationReceipt(caseCode);
      setReceipt(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve receipt.';
      alert(msg);
    } finally {
      setLoadingReceipt(false);
    }
  };

  const handleExecuteWithdrawal = async () => {
    if (!caseCode) return;
    setWithdrawing(true);
    try {
      const res = await withdrawReport(caseCode);
      setWithdrawnMessage(res.message);
      setShowWithdrawModal(false);
      // Reload case status (will now reflect WITHDRAWN / DISMISSED / Shredded)
      fetchCaseDetails(caseCode);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Withdrawal failed.';
      alert(msg);
    } finally {
      setWithdrawing(false);
    }
  };

  // If no caseCode active in memory, show input screen
  if (!caseCode) {
    return (
      <div style={{ maxWidth: 540, margin: '3rem auto' }}>
        <div className="card">
          <div className="card-header">
            <span className="card-title">Access Case Tracking Portal</span>
            <Eye size={18} color="#38bdf8" />
          </div>

          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
            Provide your 192-bit bearer case code. This code is retained in browser memory for the current tab only and is never stored in browser disk or history.
          </p>

          {error && <Alert type="danger">{error}</Alert>}

          <form onSubmit={handleManualLogin}>
            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Secret Case Code (e.g. wdc_...)
              </label>
              <input
                type="text"
                className="mono"
                placeholder="wdc_..."
                value={inputCode}
                onChange={(e) => setInputCode(e.target.value)}
                required
              />
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Authenticating & Decrypting...' : 'Open Case Portal'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Header bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              Case Tracking Portal
            </h1>
            {notifications && <StatusBadge status={notifications.status} />}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Active session: <span className="mono" style={{ color: '#38bdf8' }}>{caseCode.slice(0, 10)}...</span> (Held in memory only)
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={() => fetchCaseDetails(caseCode)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }} title="Refresh case status">
            <RefreshCw size={14} />
            Refresh
          </button>
          <button onClick={clearCaseCode} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
            Exit Session
          </button>
        </div>
      </div>

      {withdrawnMessage && (
        <Alert type="success" title="Case Successfully Withdrawn">
          {withdrawnMessage} — All encryption keys have been shredded.
        </Alert>
      )}

      {error && <Alert type="danger">{error}</Alert>}

      <div className="grid-2">
        {/* Left column: Status & Moderator Updates */}
        <div>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Investigation Status & Notifications</span>
              <Clock size={18} color="#38bdf8" />
            </div>

            {notifications && (
              <div style={{ background: '#0e1522', padding: '0.75rem', borderRadius: 6, marginBottom: '1rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Case Status:</span>
                  <StatusBadge status={notifications.status} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Status Version:</span>
                  <span className="mono">v{notifications.status_version}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Unread Messages:</span>
                  <span style={{ color: notifications.unread_messages_count > 0 ? '#f59e0b' : '#10b981', fontWeight: 600 }}>
                    {notifications.unread_messages_count}
                  </span>
                </div>
                {notifications.last_notified_at && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Last Event:</span>
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                      {new Date(notifications.last_notified_at).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>
            )}

            <div>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
                Investigation Team Communications
              </h3>

              {messages.filter((m) => m.sender_type === 'MODERATOR').length === 0 ? (
                <div style={{ color: 'var(--text-dim)', fontSize: '0.875rem', fontStyle: 'italic', padding: '1rem 0' }}>
                  No communications received from the investigation team yet. Messages will appear here and in the secure channel.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {messages
                    .filter((m) => m.sender_type === 'MODERATOR')
                    .map((update) => (
                      <div
                        key={update.id}
                        style={{
                          background: 'var(--bg-input)',
                          border: '1px solid var(--border)',
                          borderRadius: 6,
                          padding: '0.85rem',
                        }}
                      >
                        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#10b981', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                          Official Investigator Update
                        </div>
                        <div style={{ fontSize: '0.9rem', color: 'var(--text-main)', marginBottom: '0.35rem' }}>
                          {update.content}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                          {new Date(update.created_at).toLocaleString()}
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </div>
          </div>

          {/* Cryptographic Verification & Withdrawal Card */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Cryptographic Verification & Control</span>
              <ShieldCheck size={18} color="#10b981" />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <button
                onClick={handleFetchReceipt}
                disabled={loadingReceipt}
                className="btn btn-secondary"
                style={{ width: '100%', justifyContent: 'flex-start' }}
              >
                <Download size={16} />
                {loadingReceipt ? 'Verifying Receipt...' : 'Download Cryptographic Receipt'}
              </button>

              {receipt && (
                <div style={{ background: '#0a0f18', border: '1px solid #1f2d42', borderRadius: 6, padding: '0.75rem', fontSize: '0.75rem' }}>
                  <div style={{ fontWeight: 600, color: '#10b981', marginBottom: '0.3rem' }}>
                    Asymmetrically Signed Receipt (Ed25519)
                  </div>
                  <div>Reference: <span className="mono">{receipt.case_reference}</span></div>
                  <div>Key ID: <span className="mono">{receipt.key_id}</span></div>
                  <div style={{ marginTop: '0.2rem', wordBreak: 'break-all' }}>
                    Signature: <span className="mono" style={{ color: '#38bdf8' }}>{receipt.signature.slice(0, 32)}...</span>
                  </div>
                </div>
              )}

              <button
                onClick={() => setShowWithdrawModal(true)}
                className="btn btn-danger"
                style={{ width: '100%', justifyContent: 'flex-start', marginTop: '0.5rem' }}
              >
                <Trash2 size={16} />
                Withdraw Report & Irrevocably Shred Keys
              </button>
            </div>
          </div>
        </div>

        {/* Right column: Anonymous Two-Way Messaging Channel */}
        <div>
          <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '620px' }}>
            <div className="card-header">
              <span className="card-title">Secure Two-Way Channel</span>
              <MessageSquare size={18} color="#38bdf8" />
            </div>

            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '0.5rem 0',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              {messages.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem', margin: 'auto' }}>
                  No messages yet. You can submit additional information to the investigation team below.
                </div>
              ) : (
                messages.map((m) => {
                  const isReporter = m.sender_type === 'REPORTER';
                  return (
                    <div
                      key={m.id}
                      style={{
                        alignSelf: isReporter ? 'flex-end' : 'flex-start',
                        maxWidth: '85%',
                        background: isReporter ? '#1a2942' : '#1e2430',
                        border: `1px solid ${isReporter ? '#2d456b' : '#2b3648'}`,
                        borderRadius: 8,
                        padding: '0.75rem',
                      }}
                      onMouseEnter={() => {
                        if (!isReporter) acknowledgeMessageRead(caseCode, m.id).catch(() => {});
                      }}
                    >
                      <div
                        style={{
                          fontSize: '0.7rem',
                          fontWeight: 600,
                          color: isReporter ? '#38bdf8' : '#10b981',
                          textTransform: 'uppercase',
                          marginBottom: '0.2rem',
                        }}
                      >
                        {isReporter ? 'You (Whistleblower)' : 'Investigation Team'}
                      </div>
                      <div style={{ fontSize: '0.9rem', color: 'var(--text-main)', whiteSpace: 'pre-wrap' }}>
                        {m.content}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textAlign: 'right', marginTop: '0.3rem' }}>
                        {new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Message composer */}
            <form onSubmit={handleSendMessage} style={{ marginTop: '1rem', borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <textarea
                  rows={2}
                  placeholder="Send an anonymous message to the investigation team..."
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  maxLength={5000}
                  style={{ resize: 'none' }}
                />
                <button
                  type="submit"
                  disabled={!newMessage.trim() || sendingMessage}
                  className="btn btn-primary"
                  style={{ alignSelf: 'flex-end', padding: '0.65rem 0.9rem' }}
                >
                  <Send size={16} />
                </button>
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textAlign: 'right', marginTop: '0.25rem' }}>
                {newMessage.length} / 5000 characters
              </div>
            </form>
          </div>
        </div>
      </div>

      {/* Irreversible Withdrawal Confirmation Modal */}
      {showWithdrawModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <AlertTriangle size={24} color="#ef4444" />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-main)' }}>
                Irreversible Case Withdrawal
              </h3>
            </div>

            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '1rem' }}>
              Withdrawing this report will execute <strong>Unified Cryptographic Erasure</strong>:
            </p>

            <ul style={{ color: 'var(--text-muted)', fontSize: '0.85rem', paddingLeft: '1.25rem', marginBottom: '1.25rem', lineHeight: 1.6 }}>
              <li>The per-case Data Encryption Key (DEK) is permanently zeroed in PostgreSQL.</li>
              <li>All evidence attachment DEKs are destroyed within the same database transaction.</li>
              <li>Existing text payloads and binary files become mathematically unrecoverable across all storage.</li>
              <li>This action is permanent and cannot be undone by administrators.</li>
            </ul>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setShowWithdrawModal(false)}
                className="btn btn-secondary"
                disabled={withdrawing}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteWithdrawal}
                disabled={withdrawing}
                className="btn btn-danger"
              >
                {withdrawing ? 'Shredding Keys...' : 'Confirm & Shred All Data'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
