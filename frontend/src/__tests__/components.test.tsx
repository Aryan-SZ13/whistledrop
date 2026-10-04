import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { Navbar } from '../components/Navbar';
import { StatusBadge, PriorityBadge } from '../components/Badge';
import { AnonymousProvider } from '../context/AnonymousContext';
import { AuthProvider } from '../context/AuthContext';

describe('Frontend Components & Integration Flows', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders StatusBadge and PriorityBadge correctly', () => {
    const { container: sContainer } = render(<StatusBadge status="UNDER_REVIEW" />);
    expect(screen.getByText('UNDER REVIEW')).toBeDefined();
    expect(sContainer.querySelector('.badge-under_review')).not.toBeNull();

    const { container: pContainer } = render(<PriorityBadge priority="CRITICAL" />);
    expect(screen.getByText('CRITICAL')).toBeDefined();
    expect(pContainer.querySelector('.badge-critical')).not.toBeNull();
  });

  it('renders Navbar with zero-IP policy indicator', () => {
    render(
      <AuthProvider>
        <AnonymousProvider>
          <Navbar currentTab="submit" onSelectTab={vi.fn()} />
        </AnonymousProvider>
      </AuthProvider>
    );

    expect(screen.getByText('WhistleDrop')).toBeDefined();
    expect(screen.getByText('Submit Report')).toBeDefined();
    expect(screen.getByText('Track Case')).toBeDefined();
    expect(screen.getByText('Transparency & Canary')).toBeDefined();
    expect(screen.getByText('Zero-IP Logging')).toBeDefined();
  });

  it('renders SubmitReportPage within App and validates form fields', async () => {
    render(<App />);

    expect(screen.getAllByText('Submit Confidential Report').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByPlaceholderText('Brief summary of the incident or misconduct')).toBeDefined();
    expect(screen.getByText('Incident Category *')).toBeDefined();
    expect(screen.getByText('Detailed Narrative *')).toBeDefined();
  });

  it('navigates to Track Case tab and shows case code input prompt', async () => {
    render(<App />);

    const trackBtn = screen.getByText('Track Case');
    fireEvent.click(trackBtn);

    expect(screen.getByText('Access Case Tracking Portal')).toBeDefined();
    expect(screen.getByPlaceholderText('wdc_...')).toBeDefined();
    expect(screen.getByText('Open Case Portal')).toBeDefined();
  });

  it('navigates to Transparency & Canary tab and displays log state', async () => {
    const mockSTH = {
      tree_size: 42,
      root_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      timestamp: '2026-10-04T12:00:00Z',
      signature: 'ed25519_mock_signature',
      signing_key_id: 'transparency-v1',
    };

    const mockCanary = {
      statement_serial: 1,
      statement_text: 'No national security letters received.',
      statement_hash: 'hash123',
      issued_at: '2026-10-01T00:00:00Z',
      valid_until: '2026-10-15T00:00:00Z',
      signature: 'canary_sig',
      signing_key_id: 'canary-v1',
      status: 'ACTIVE_VALID',
      is_active: true,
    };

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/transparency/sth')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => mockSTH,
        });
      }
      if (url.includes('/canary/latest')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => mockCanary,
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => [],
      });
    });

    render(<App />);

    const transpBtn = screen.getByText('Transparency & Canary');
    fireEvent.click(transpBtn);

    expect(screen.getByText('Merkle Transparency & Warrant Canary Hub')).toBeDefined();
    await waitFor(() => {
      expect(screen.getByText('42 leaves')).toBeDefined();
      expect(screen.getByText('No national security letters received.')).toBeDefined();
    });
  });

  it('navigates to Moderator Portal and shows login form', async () => {
    render(<App />);

    const modBtn = screen.getByText('Staff Login');
    fireEvent.click(modBtn);

    expect(screen.getByText('Moderator Control Plane')).toBeDefined();
    expect(screen.getByPlaceholderText('Enter moderator username')).toBeDefined();
    expect(screen.getByPlaceholderText('Enter secure password')).toBeDefined();
  });
});
