import React from 'react';
import { Shield, Eye, Lock, FileText, Activity, LogOut, CheckCircle2 } from 'lucide-react';
import { useAnonymous } from '../context/AnonymousContext';
import { useAuth } from '../context/AuthContext';

export type NavTab = 'submit' | 'track' | 'transparency' | 'moderator' | 'admin';

interface NavbarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab }) => {
  const { hasActiveSession, clearCaseCode } = useAnonymous();
  const { isAuthenticated, logout } = useAuth();

  return (
    <header className="header-nav">
      <div className="brand" onClick={() => onSelectTab('submit')}>
        <Shield size={22} className="text-sky-400" color="#38bdf8" />
        <span>WhistleDrop</span>
        <span className="brand-badge">Privacy First</span>
      </div>

      <nav className="nav-links">
        <button
          className={`nav-btn ${currentTab === 'submit' ? 'active' : ''}`}
          onClick={() => onSelectTab('submit')}
        >
          <FileText size={16} />
          Submit Report
        </button>

        <button
          className={`nav-btn ${currentTab === 'track' ? 'active' : ''}`}
          onClick={() => onSelectTab('track')}
        >
          <Eye size={16} />
          Track Case
          {hasActiveSession && (
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                backgroundColor: '#10b981',
                marginLeft: 3,
              }}
              title="Active In-Memory Session"
            />
          )}
        </button>

        <button
          className={`nav-btn ${currentTab === 'transparency' ? 'active' : ''}`}
          onClick={() => onSelectTab('transparency')}
        >
          <Activity size={16} />
          Transparency & Canary
        </button>

        <button
          className={`nav-btn ${currentTab === 'moderator' ? 'active' : ''}`}
          onClick={() => onSelectTab('moderator')}
        >
          <Lock size={16} />
          {isAuthenticated ? 'Moderator Portal' : 'Staff Login'}
        </button>

        {isAuthenticated && (
          <button
            className={`nav-btn ${currentTab === 'admin' ? 'active' : ''}`}
            onClick={() => onSelectTab('admin')}
          >
            <Shield size={16} />
            Security & Quorum
          </button>
        )}
      </nav>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {hasActiveSession && (
          <button
            onClick={clearCaseCode}
            className="btn btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
            title="Clear active in-memory case code session"
          >
            Clear In-Memory Case
          </button>
        )}

        {isAuthenticated && (
          <button
            onClick={() => logout()}
            className="btn btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
          >
            <LogOut size={13} />
            Logout
          </button>
        )}

        <div
          style={{
            fontSize: '0.75rem',
            color: 'var(--text-dim)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            borderLeft: '1px solid var(--border)',
            paddingLeft: '0.75rem',
          }}
        >
          <CheckCircle2 size={13} color="#10b981" />
          <span>Zero-IP Logging</span>
        </div>
      </div>
    </header>
  );
};
