import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import type { NavTab } from './components/Navbar';
import { AnonymousProvider } from './context/AnonymousContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SubmitReportPage } from './pages/SubmitReportPage';
import { TrackCasePage } from './pages/TrackCasePage';
import { TransparencyPage } from './pages/TransparencyPage';
import { ModeratorLoginPage } from './pages/ModeratorLoginPage';
import { ModeratorDashboardPage } from './pages/ModeratorDashboardPage';
import { ModeratorCaseDetailPage } from './pages/ModeratorCaseDetailPage';
import { AdminSecurityPage } from './pages/AdminSecurityPage';

const AppContent: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('submit');
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const { isAuthenticated } = useAuth();

  const handleSelectTab = (tab: NavTab) => {
    setCurrentTab(tab);
    if (tab !== 'moderator') {
      setSelectedReportId(null);
    }
  };

  const renderCurrentView = () => {
    switch (currentTab) {
      case 'submit':
        return <SubmitReportPage onNavigateToTrack={() => handleSelectTab('track')} />;
      case 'track':
        return <TrackCasePage />;
      case 'transparency':
        return <TransparencyPage />;
      case 'moderator':
        if (!isAuthenticated) {
          return <ModeratorLoginPage onLoginSuccess={() => handleSelectTab('moderator')} />;
        }
        if (selectedReportId) {
          return (
            <ModeratorCaseDetailPage
              reportId={selectedReportId}
              onBack={() => setSelectedReportId(null)}
            />
          );
        }
        return (
          <ModeratorDashboardPage
            onSelectReport={(reportId) => setSelectedReportId(reportId)}
          />
        );
      case 'admin':
        if (!isAuthenticated) {
          return <ModeratorLoginPage onLoginSuccess={() => handleSelectTab('admin')} />;
        }
        return <AdminSecurityPage />;
      default:
        return <SubmitReportPage onNavigateToTrack={() => handleSelectTab('track')} />;
    }
  };

  return (
    <div className="app-container">
      <Navbar currentTab={currentTab} onSelectTab={handleSelectTab} />

      <main className="main-content">
        {renderCurrentView()}
      </main>

      <footer
        style={{
          borderTop: '1px solid var(--border)',
          background: 'var(--bg-card)',
          padding: '1.25rem 1.5rem',
          textAlign: 'center',
          fontSize: '0.75rem',
          color: 'var(--text-dim)',
        }}
      >
        <div style={{ maxWidth: 1180, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            WhistleDrop Security Platform • Application-Level Envelope Encryption (ALEE) • RFC 6962 Merkle Transparency
          </div>
          <div>
            Zero-IP Logging Guaranteed • No Persistent Client-Side Credentials
          </div>
        </div>
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AnonymousProvider>
        <AppContent />
      </AnonymousProvider>
    </AuthProvider>
  );
};

export default App;
