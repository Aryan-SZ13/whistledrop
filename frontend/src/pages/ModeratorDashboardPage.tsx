import React, { useState, useEffect, useCallback } from 'react';
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react';
import { getDashboardStats, listReports } from '../api/moderator';
import { Alert } from '../components/Alert';
import { StatusBadge, PriorityBadge } from '../components/Badge';
import { useAuth } from '../context/AuthContext';
import type {
  DashboardStats,
  ModeratorReportListItem,
  ReportCategory,
  ReportPriority,
  ReportStatus,
} from '../types';

interface ModeratorDashboardPageProps {
  onSelectReport: (reportId: string) => void;
}

export const ModeratorDashboardPage: React.FC<ModeratorDashboardPageProps> = ({ onSelectReport }) => {
  const { token } = useAuth();

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [reports, setReports] = useState<ModeratorReportListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters & Pagination
  const [statusFilter, setStatusFilter] = useState<ReportStatus | ''>('');
  const [categoryFilter, setCategoryFilter] = useState<ReportCategory | ''>('');
  const [priorityFilter, setPriorityFilter] = useState<ReportPriority | ''>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 15;

  const fetchReports = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [statsRes, listRes] = await Promise.all([
        getDashboardStats(token).catch(() => null),
        listReports(token, {
          status: statusFilter || undefined,
          category: categoryFilter || undefined,
          priority: priorityFilter || undefined,
          search: searchQuery.trim() || undefined,
          limit,
          offset,
        }),
      ]);
      if (statsRes) setStats(statsRes);
      setReports(listRes.items || []);
      setTotal(listRes.total || 0);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve cases.');
    } finally {
      setLoading(false);
    }
  }, [token, statusFilter, categoryFilter, priorityFilter, searchQuery, offset, limit]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  return (
    <div>
      {/* Top bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
            Investigation Triage Dashboard
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.2rem' }}>
            Authorized personnel workspace under Optimistic Concurrency Control (OCC)
          </p>
        </div>

        <button onClick={fetchReports} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {error && <Alert type="danger">{error}</Alert>}

      {/* Metrics Row */}
      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">Total Ingested</div>
            <div className="stat-value">{stats.total_reports}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Unassigned Cases</div>
            <div className="stat-value" style={{ color: stats.unassigned_reports > 0 ? '#f59e0b' : '#10b981' }}>
              {stats.unassigned_reports}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Critical Priority</div>
            <div className="stat-value" style={{ color: (stats.by_priority?.['CRITICAL'] || 0) > 0 ? '#ef4444' : 'var(--text-main)' }}>
              {stats.by_priority?.['CRITICAL'] || 0}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">My Active Cases</div>
            <div className="stat-value" style={{ color: '#38bdf8' }}>
              {stats.my_active_cases}
            </div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '1rem', marginBottom: '1rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
          <div>
            <input
              type="text"
              placeholder="Search title/desc..."
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setOffset(0); }}
            />
          </div>

          <div>
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value as ReportStatus | ''); setOffset(0); }}
            >
              <option value="">All Statuses</option>
              <option value="SUBMITTED">Submitted</option>
              <option value="UNDER_REVIEW">Under Review</option>
              <option value="RESOLVED">Resolved</option>
              <option value="DISMISSED">Dismissed</option>
            </select>
          </div>

          <div>
            <select
              value={priorityFilter}
              onChange={(e) => { setPriorityFilter(e.target.value as ReportPriority | ''); setOffset(0); }}
            >
              <option value="">All Priorities</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>

          <div>
            <select
              value={categoryFilter}
              onChange={(e) => { setCategoryFilter(e.target.value as ReportCategory | ''); setOffset(0); }}
            >
              <option value="">All Categories</option>
              <option value="FINANCIAL_MISCONDUCT">Financial</option>
              <option value="CORRUPTION_BRIBERY">Corruption</option>
              <option value="SAFETY_HEALTH_VIOLATION">Safety/Health</option>
              <option value="ENVIRONMENTAL_DAMAGE">Environmental</option>
              <option value="DATA_PRIVACY_BREACH">Data Privacy</option>
              <option value="HARASSMENT_DISCRIMINATION">Harassment</option>
              <option value="OTHER">Other</option>
            </select>
          </div>
        </div>
      </div>

      {/* Cases Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Title</th>
              <th>Category</th>
              <th>Status</th>
              <th>Priority</th>
              <th>Version</th>
              <th>Submitted</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                  Loading investigations...
                </td>
              </tr>
            ) : reports.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                  No reports matching current filter criteria.
                </td>
              </tr>
            ) : (
              reports.map((report) => (
                <tr
                  key={report.id}
                  onClick={() => onSelectReport(report.id)}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ fontWeight: 600 }}>{report.title}</td>
                  <td>{report.category.replace('_', ' ')}</td>
                  <td><StatusBadge status={report.status} /></td>
                  <td><PriorityBadge priority={report.priority} /></td>
                  <td><span className="mono" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>v{report.version_id}</span></td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {new Date(report.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem 1rem', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Showing {reports.length > 0 ? offset + 1 : 0} to {Math.min(offset + limit, total)} of {total} cases
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => setOffset((prev) => Math.max(0, prev - limit))}
              disabled={offset === 0}
              className="btn btn-secondary"
              style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
            >
              <ChevronLeft size={14} />
              Previous
            </button>
            <button
              onClick={() => setOffset((prev) => prev + limit)}
              disabled={offset + limit >= total}
              className="btn btn-secondary"
              style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
