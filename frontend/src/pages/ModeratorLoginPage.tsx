import React, { useState } from 'react';
import { Lock, ArrowRight } from 'lucide-react';
import { login, mfaChallenge } from '../api/moderator';
import { Alert } from '../components/Alert';
import { useAuth } from '../context/AuthContext';

interface ModeratorLoginPageProps {
  onLoginSuccess: () => void;
}

export const ModeratorLoginPage: React.FC<ModeratorLoginPageProps> = ({ onLoginSuccess }) => {
  const { setAuthTokens } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA challenge step
  const [challengeTicket, setChallengeTicket] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');

  const handleInitialLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await login(username.trim(), password);
      if (res.requires_mfa && res.challenge_ticket) {
        setChallengeTicket(res.challenge_ticket);
      } else if (res.access_token) {
        setAuthTokens(res.access_token, res.refresh_token);
        onLoginSuccess();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!challengeTicket || !totpCode.trim()) return;

    setError(null);
    setLoading(true);

    try {
      const res = await mfaChallenge(challengeTicket, totpCode.trim());
      if (res.access_token) {
        setAuthTokens(res.access_token, res.refresh_token);
        onLoginSuccess();
      } else {
        setError('Invalid authentication response from server.');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid MFA verification code.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 440, margin: '3.5rem auto' }}>
      <div className="card">
        <div className="card-header" style={{ justifyContent: 'center', textAlign: 'center', borderBottom: 'none' }}>
          <div>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: '50%',
                background: 'rgba(56, 189, 248, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.75rem auto',
              }}
            >
              <Lock size={22} color="#38bdf8" />
            </div>
            <h2 className="card-title" style={{ fontSize: '1.3rem' }}>
              Moderator Control Plane
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.25rem' }}>
              Restricted access for verified investigative personnel
            </p>
          </div>
        </div>

        {error && <Alert type="danger">{error}</Alert>}

        {!challengeTicket ? (
          /* Step 1: Credentials */
          <form onSubmit={handleInitialLogin}>
            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Username
              </label>
              <input
                type="text"
                placeholder="Enter moderator username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
              />
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Password
              </label>
              <input
                type="password"
                placeholder="Enter secure password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>

            <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: '100%' }}>
              {loading ? 'Authenticating...' : 'Sign In'}
              <ArrowRight size={16} />
            </button>
          </form>
        ) : (
          /* Step 2: Live MFA Challenge */
          <form onSubmit={handleMfaSubmit}>
            <Alert type="info" title="Two-Factor Authentication Required">
              Enter the 6-digit TOTP code from your registered authenticator application or emergency recovery code.
            </Alert>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                6-Digit Authenticator Code
              </label>
              <input
                type="text"
                className="mono"
                placeholder="123456"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                maxLength={6}
                autoFocus
                required
                style={{ textAlign: 'center', fontSize: '1.25rem', letterSpacing: '0.2em' }}
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => { setChallengeTicket(null); setTotpCode(''); }}
                className="btn btn-secondary"
                style={{ flex: 1 }}
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading || totpCode.length < 6}
                className="btn btn-primary"
                style={{ flex: 2 }}
              >
                {loading ? 'Verifying...' : 'Verify MFA'}
              </button>
            </div>
          </form>
        )}

        <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
          Session tokens are securely bound and monitored for replay anomalies.
        </div>
      </div>
    </div>
  );
};
