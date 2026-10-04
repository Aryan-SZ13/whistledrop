import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowLeft,
  Clock,
  FileText,
  MessageSquare,
  ShieldAlert,
  Download,
  CheckCircle2,
  Key,
  Send,
} from 'lucide-react';
import {
  getReportDetail,
  updateReportStatus,
  updateReportPriority,
  postReportUpdate,
  getReportTimeline,
  listModeratorMessages,
  postModeratorMessage,
  listEvidence,
  getEvidenceDownloadUrl,
  getArchiveExportUrl,
  verifyAuditChain,
  rewrapKeys,
} from '../api/moderator';
import { Alert } from '../components/Alert';
import { StatusBadge, PriorityBadge } from '../components/Badge';
import { useAuth } from '../context/AuthContext';
import type {
  ModeratorReportDetail,
  EvidenceAttachmentItem,
  TimelineEventItem,
  CaseMessagePublic,
  ReportPriority,
  ReportStatus,
  ReportUpdateType,
} from '../types';

interface ModeratorCaseDetailPageProps {
  reportId: string;
  onBack: () => void;
}

export const ModeratorCaseDetailPage: React.FC<ModeratorCaseDetailPageProps> = ({ reportId, onBack }) => {
  const { token } = useAuth();

  const [report, setReport] = useState<ModeratorReportDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Active Tab
  const [activeTab, setActiveTab] = useState<'timeline' | 'evidence' | 'messages' | 'update'>('timeline');

  // Tab Data
  const [timeline, setTimeline] = useState<TimelineEventItem[]>([]);
  const [evidence, setEvidence] = useState<EvidenceAttachmentItem[]>([]);
  const [messages, setMessages] = useState<CaseMessagePublic[]>([]);

  // Post update state
  const [updateType, setUpdateType] = useState<ReportUpdateType>('PUBLIC_UPDATE');
  const [updateMessage, setUpdateMessage] = useState('');
  const [postingUpdate, setPostingUpdate] = useState(false);

  // Post message state
  const [newMessage, setNewMessage] = useState('');
  const [sendingMessage, setSendingMessage] = useState(false);

  // Status mutation state
  const [statusVal, setStatusVal] = useState<ReportStatus>('SUBMITTED');
  const [priorityVal, setPriorityVal] = useState<ReportPriority>('MEDIUM');
  const [reopenReason, setReopenReason] = useState('');
  const [mutating, setMutating] = useState(false);

  // Audit verify & Rewrap state
  const [auditResult, setAuditResult] = useState<string | null>(null);
  const [rewrapResult, setRewrapResult] = useState<string | null>(null);

  const fetchDetail = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getReportDetail(token, reportId);
      setReport(res);
      setStatusVal(res.status);
      setPriorityVal(res.priority);

      // Load sub-resources
      const [tlRes, evRes, msgRes] = await Promise.all([
        getReportTimeline(token, reportId).catch(() => ({ items: [] })),
        listEvidence(token, reportId).catch(() => []),
        listModeratorMessages(token, reportId).catch(() => ({ items: [] })),
      ]);
      setTimeline(tlRes.items || []);
      setEvidence(evRes || []);
      setMessages(msgRes.items || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve report detail.');
    } finally {
      setLoading(false);
    }
  }, [token, reportId]);

  useEffect(() => {
    fetchDetail();
  }, [fetchDetail]);

  const handleStatusChange = async (newStatus: ReportStatus) => {
    if (!token || !report) return;
    setMutating(true);
    try {
      await updateReportStatus(
        token,
        report.id,
        newStatus,
        report.version_id,
        reopenReason || undefined
      );
      setReopenReason('');
      await fetchDetail();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Status update failed (Check OCC version).');
    } finally {
      setMutating(false);
    }
  };

  const handlePriorityChange = async (newPriority: ReportPriority) => {
    if (!token || !report) return;
    setMutating(true);
    try {
      await updateReportPriority(token, report.id, newPriority, report.version_id);
      await fetchDetail();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Priority update failed.');
    } finally {
      setMutating(false);
    }
  };

  const handlePostUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !report || !updateMessage.trim()) return;

    setPostingUpdate(true);
    try {
      await postReportUpdate(token, report.id, updateType, updateMessage.trim(), report.version_id);
      setUpdateMessage('');
      await fetchDetail();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Update failed (OCC version mismatch).');
    } finally {
      setPostingUpdate(false);
    }
  };

  const handlePostMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !report || !newMessage.trim()) return;

    setSendingMessage(true);
    try {
      await postModeratorMessage(token, report.id, newMessage.trim());
      setNewMessage('');
      const msgRes = await listModeratorMessages(token, reportId);
      setMessages(msgRes.items || []);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Message post failed.');
    } finally {
      setSendingMessage(false);
    }
  };

  const handleVerifyAudit = async () => {
    if (!token || !report) return;
    try {
      const res = await verifyAuditChain(token, report.id);
      setAuditResult(
        res.is_valid
          ? `Verified! Chain length: ${res.chain_length} entries. Hash: ${res.terminal_hash.slice(0, 16)}...`
          : 'Verification failed: Audit chain integrity violation detected.'
      );
    } catch (err: unknown) {
      setAuditResult(err instanceof Error ? err.message : 'Audit chain verification error.');
    }
  };

  const handleRewrap = async () => {
    if (!token || !report) return;
    try {
      const res = await rewrapKeys(token, report.id);
      setRewrapResult(`Case DEK successfully rewrapped under KEK version ${res.new_key_version}.`);
    } catch (err: unknown) {
      setRewrapResult(err instanceof Error ? err.message : 'Key rewrap failed.');
    }
  };

  if (loading && !report) {
    return <div style={{ color: 'var(--text-dim)', padding: '2rem' }}>Decrypting and loading investigation record...</div>;
  }

  if (!report) {
    return (
      <div>
        {error && <Alert type="danger">{error}</Alert>}
        <button onClick={onBack} className="btn btn-secondary">
          <ArrowLeft size={16} />
          Back to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div>
      {/* Top action bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <button onClick={onBack} className="btn btn-secondary" style={{ fontSize: '0.85rem' }}>
          <ArrowLeft size={15} />
          Back to Dashboard
        </button>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span className="mono" style={{ fontSize: '0.8rem', color: '#94a3b8', background: '#0e1624', padding: '0.35rem 0.65rem', borderRadius: 4, border: '1px solid var(--border)' }}>
            OCC: v{report.version_id}
          </span>
          <a
            href={getArchiveExportUrl(report.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-secondary"
            style={{ fontSize: '0.8rem' }}
          >
            <Download size={14} />
            Export Archive
          </a>
          <button onClick={handleVerifyAudit} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
            <CheckCircle2 size={14} color="#10b981" />
            Verify Audit Chain
          </button>
          <button onClick={handleRewrap} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
            <Key size={14} color="#38bdf8" />
            Rewrap Key
          </button>
        </div>
      </div>

      {auditResult && <Alert type="info">{auditResult}</Alert>}
      {rewrapResult && <Alert type="success">{rewrapResult}</Alert>}
      {error && <Alert type="danger">{error}</Alert>}

      {/* Case Overview Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border)', paddingBottom: '1rem', marginBottom: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
              <StatusBadge status={report.status} />
              <PriorityBadge priority={report.priority} />
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {report.category.replace('_', ' ')}
              </span>
            </div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              {report.title}
            </h1>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
              Case UUID: <span className="mono">{report.id}</span> • Ingested: {new Date(report.created_at).toLocaleString()}
            </div>
          </div>

          {/* Controls */}
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>
                Status
              </label>
              <select
                value={statusVal}
                onChange={(e) => {
                  const s = e.target.value as ReportStatus;
                  setStatusVal(s);
                  handleStatusChange(s);
                }}
                disabled={mutating}
                style={{ fontSize: '0.8rem', padding: '0.4rem 0.6rem' }}
              >
                <option value="SUBMITTED">Submitted</option>
                <option value="UNDER_REVIEW">Under Review</option>
                <option value="RESOLVED">Resolved</option>
                <option value="DISMISSED">Dismissed</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>
                Priority
              </label>
              <select
                value={priorityVal}
                onChange={(e) => {
                  const p = e.target.value as ReportPriority;
                  setPriorityVal(p);
                  handlePriorityChange(p);
                }}
                disabled={mutating}
                style={{ fontSize: '0.8rem', padding: '0.4rem 0.6rem' }}
              >
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </div>
          </div>
        </div>

        {/* Decrypted Payload */}
        <div>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.4rem' }}>
            Decrypted Narrative (ALEE In-Memory Decryption)
          </div>
          <div
            style={{
              background: '#090e17',
              border: '1px solid #1c293d',
              borderRadius: 6,
              padding: '1rem',
              fontSize: '0.9rem',
              lineHeight: 1.6,
              color: 'var(--text-main)',
              whiteSpace: 'pre-wrap',
            }}
          >
            {report.description}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border)', marginBottom: '1.25rem' }}>
        <button
          className={`nav-btn ${activeTab === 'timeline' ? 'active' : ''}`}
          onClick={() => setActiveTab('timeline')}
          style={{ borderRadius: '6px 6px 0 0', padding: '0.6rem 1rem' }}
        >
          <Clock size={15} />
          Case Timeline ({timeline.length})
        </button>

        <button
          className={`nav-btn ${activeTab === 'evidence' ? 'active' : ''}`}
          onClick={() => setActiveTab('evidence')}
          style={{ borderRadius: '6px 6px 0 0', padding: '0.6rem 1rem' }}
        >
          <FileText size={15} />
          Evidence Attachments ({evidence.length})
        </button>

        <button
          className={`nav-btn ${activeTab === 'messages' ? 'active' : ''}`}
          onClick={() => setActiveTab('messages')}
          style={{ borderRadius: '6px 6px 0 0', padding: '0.6rem 1rem' }}
        >
          <MessageSquare size={15} />
          Whistleblower Messages ({messages.length})
        </button>

        <button
          className={`nav-btn ${activeTab === 'update' ? 'active' : ''}`}
          onClick={() => setActiveTab('update')}
          style={{ borderRadius: '6px 6px 0 0', padding: '0.6rem 1rem' }}
        >
          <ShieldAlert size={15} />
          Post Update / Note
        </button>
      </div>

      {/* Tab 1: Timeline */}
      {activeTab === 'timeline' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Chronological Unified Timeline</span>
          </div>
          {timeline.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No events recorded.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {timeline.map((ev) => (
                <div key={ev.event_id} style={{ borderLeft: '2px solid var(--accent)', paddingLeft: '1rem', marginLeft: '0.5rem' }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>{ev.summary}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.15rem' }}>
                    {ev.event_type} • {new Date(ev.event_timestamp).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Evidence */}
      {activeTab === 'evidence' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Evidence Attachments (Envelope Encrypted)</span>
          </div>
          {evidence.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No evidence attached to this report.</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Attachment Key</th>
                  <th>MIME Type</th>
                  <th>Scan Status</th>
                  <th>Size</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((att) => (
                  <tr key={att.id}>
                    <td className="mono" style={{ fontSize: '0.8rem' }}>{att.storage_key}</td>
                    <td>{att.content_type}</td>
                    <td>
                      <span className={`badge ${att.scan_status === 'CLEAN' ? 'badge-resolved' : 'badge-under_review'}`}>
                        {att.scan_status}
                      </span>
                    </td>
                    <td>{(att.file_size_bytes / 1024).toFixed(0)} KB</td>
                    <td>
                      {att.scan_status === 'CLEAN' ? (
                        <a
                          href={getEvidenceDownloadUrl(report.id, att.id)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                        >
                          <Download size={12} />
                          Download
                        </a>
                      ) : (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Scan Blocked</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 3: Whistleblower Messages */}
      {activeTab === 'messages' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Encrypted Anonymous Communication Channel</span>
          </div>

          <div style={{ maxHeight: 380, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem', padding: '0.5rem 0' }}>
            {messages.length === 0 ? (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No messages sent yet.</div>
            ) : (
              messages.map((m) => {
                const isModerator = m.sender_type === 'MODERATOR';
                return (
                  <div
                    key={m.id}
                    style={{
                      alignSelf: isModerator ? 'flex-end' : 'flex-start',
                      maxWidth: '85%',
                      background: isModerator ? '#132035' : '#1e2430',
                      border: `1px solid ${isModerator ? '#243b61' : '#2b3648'}`,
                      borderRadius: 8,
                      padding: '0.75rem',
                    }}
                  >
                    <div style={{ fontSize: '0.7rem', fontWeight: 600, color: isModerator ? '#38bdf8' : '#10b981', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                      {isModerator ? 'You (Moderator)' : 'Whistleblower'}
                    </div>
                    <div style={{ fontSize: '0.9rem', color: 'var(--text-main)', whiteSpace: 'pre-wrap' }}>{m.content}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textAlign: 'right', marginTop: '0.3rem' }}>
                      {new Date(m.created_at).toLocaleString()}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <form onSubmit={handlePostMessage} style={{ borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <textarea
                rows={2}
                placeholder="Post reply to whistleblower..."
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                maxLength={5000}
                style={{ resize: 'none' }}
              />
              <button type="submit" disabled={!newMessage.trim() || sendingMessage} className="btn btn-primary" style={{ alignSelf: 'flex-end', padding: '0.65rem 0.9rem' }}>
                <Send size={16} />
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 4: Post Update / Note */}
      {activeTab === 'update' && (
        <form onSubmit={handlePostUpdate} className="card">
          <div className="card-header">
            <span className="card-title">Add Case Update or Internal Investigation Note</span>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
              Update Visibility Scope *
            </label>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.85rem' }}>
                <input
                  type="radio"
                  name="updateType"
                  checked={updateType === 'PUBLIC_UPDATE'}
                  onChange={() => setUpdateType('PUBLIC_UPDATE')}
                  style={{ width: 'auto' }}
                />
                <span>Public Status Update (Visible to anonymous reporter)</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.85rem' }}>
                <input
                  type="radio"
                  name="updateType"
                  checked={updateType === 'INTERNAL_NOTE'}
                  onChange={() => setUpdateType('INTERNAL_NOTE')}
                  style={{ width: 'auto' }}
                />
                <span>Internal Note (Moderator team only)</span>
              </label>
            </div>
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
              Content Narrative *
            </label>
            <textarea
              rows={4}
              placeholder={updateType === 'PUBLIC_UPDATE' ? 'Progress update for the whistleblower...' : 'Confidential internal assessment note...'}
              value={updateMessage}
              onChange={(e) => setUpdateMessage(e.target.value)}
              required
            />
          </div>

          <button type="submit" disabled={postingUpdate} className="btn btn-primary">
            {postingUpdate ? 'Committing...' : 'Commit Update with OCC (v' + report.version_id + ')'}
          </button>
        </form>
      )}
    </div>
  );
};
