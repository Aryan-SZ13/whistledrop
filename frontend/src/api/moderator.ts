import { apiRequest } from './client';
import type {
  CaseMessageListResponse,
  DashboardStats,
  EvidenceAttachmentItem,
  LoginResponse,
  ModeratorReportDetail,
  ModeratorReportListResponse,
  QuorumProposal,
  ReportPriority,
  ReportStatus,
  ReportUpdateType,
  SecurityStateResponse,
  TimelineEventItem,
  WebhookEndpointItem,
} from '../types';

export async function login(username: string, password: string): Promise<LoginResponse> {
  return apiRequest<LoginResponse>('/auth/login', {
    method: 'POST',
    body: { username, password },
  });
}

export async function mfaChallenge(challengeTicket: string, totpCode: string): Promise<LoginResponse> {
  return apiRequest<LoginResponse>('/auth/mfa/challenge', {
    method: 'POST',
    body: { challenge_ticket: challengeTicket, totp_code: totpCode },
  });
}

export async function refreshToken(token: string): Promise<LoginResponse> {
  return apiRequest<LoginResponse>('/auth/refresh', {
    method: 'POST',
    body: { refresh_token: token },
  });
}

export async function logout(token: string): Promise<{ status: string }> {
  return apiRequest('/auth/logout', {
    method: 'POST',
    token,
  });
}

export async function getDashboardStats(token: string): Promise<DashboardStats> {
  return apiRequest<DashboardStats>('/moderator/dashboard/stats', {
    method: 'GET',
    token,
  });
}

export interface ListReportsParams {
  status?: ReportStatus;
  category?: string;
  priority?: ReportPriority;
  assigned_to?: string;
  search?: string;
  sort_by?: 'created_at' | 'updated_at' | 'priority';
  sort_order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}

export async function listReports(
  token: string,
  params: ListReportsParams = {}
): Promise<ModeratorReportListResponse> {
  const query = new URLSearchParams();
  if (params.status) query.set('status', params.status);
  if (params.category) query.set('category', params.category);
  if (params.priority) query.set('priority', params.priority);
  if (params.assigned_to) query.set('assigned_to', params.assigned_to);
  if (params.search) query.set('search', params.search);
  if (params.sort_by) query.set('sort_by', params.sort_by);
  if (params.sort_order) query.set('sort_order', params.sort_order);
  if (params.limit !== undefined) query.set('limit', params.limit.toString());
  if (params.offset !== undefined) query.set('offset', params.offset.toString());

  return apiRequest<ModeratorReportListResponse>(`/moderator/reports?${query.toString()}`, {
    method: 'GET',
    token,
  });
}

export async function getReportDetail(token: string, reportId: string): Promise<ModeratorReportDetail> {
  return apiRequest<ModeratorReportDetail>(`/moderator/reports/${reportId}`, {
    method: 'GET',
    token,
  });
}

export async function updateReportStatus(
  token: string,
  reportId: string,
  status: ReportStatus,
  expectedVersion: number,
  reopenReason?: string
): Promise<{ status: string; report_id: string; new_version: number }> {
  return apiRequest(`/moderator/reports/${reportId}/status`, {
    method: 'PATCH',
    token,
    body: { status, expected_version: expectedVersion, reopen_reason: reopenReason },
  });
}

export async function updateReportPriority(
  token: string,
  reportId: string,
  priority: ReportPriority,
  expectedVersion: number
): Promise<{ status: string; report_id: string; new_version: number }> {
  return apiRequest(`/moderator/reports/${reportId}/priority`, {
    method: 'PATCH',
    token,
    body: { priority, expected_version: expectedVersion },
  });
}

export async function updateReportAssignment(
  token: string,
  reportId: string,
  assignedToId: string | null,
  expectedVersion: number
): Promise<{ status: string; report_id: string; new_version: number }> {
  return apiRequest(`/moderator/reports/${reportId}/assignment`, {
    method: 'PATCH',
    token,
    body: { assigned_to: assignedToId, expected_version: expectedVersion },
  });
}

export async function postReportUpdate(
  token: string,
  reportId: string,
  updateType: ReportUpdateType,
  message: string,
  expectedVersion: number
): Promise<{ status: string; update_id: string; new_version: number }> {
  return apiRequest(`/moderator/reports/${reportId}/updates`, {
    method: 'POST',
    token,
    body: { update_type: updateType, message, expected_version: expectedVersion },
  });
}

export async function getReportTimeline(
  token: string,
  reportId: string,
  cursor: string | null = null,
  limit: number = 50
): Promise<{ items: TimelineEventItem[]; next_cursor: string | null; has_more: boolean }> {
  const query = new URLSearchParams();
  if (cursor) query.set('cursor', cursor);
  query.set('limit', limit.toString());

  return apiRequest(`/moderator/reports/${reportId}/timeline?${query.toString()}`, {
    method: 'GET',
    token,
  });
}

export async function listModeratorMessages(
  token: string,
  reportId: string,
  cursor: string | null = null,
  limit: number = 50
): Promise<CaseMessageListResponse> {
  const query = new URLSearchParams();
  if (cursor) query.set('cursor', cursor);
  query.set('limit', limit.toString());

  return apiRequest<CaseMessageListResponse>(`/moderator/reports/${reportId}/messages?${query.toString()}`, {
    method: 'GET',
    token,
  });
}

export async function postModeratorMessage(
  token: string,
  reportId: string,
  content: string
): Promise<{ status: string; message_id: string }> {
  return apiRequest(`/moderator/reports/${reportId}/messages`, {
    method: 'POST',
    token,
    body: { content },
  });
}

export async function acknowledgeModeratorMessageRead(
  token: string,
  reportId: string,
  messageId: string
): Promise<{ status: string }> {
  return apiRequest(`/moderator/reports/${reportId}/messages/read`, {
    method: 'POST',
    token,
    body: { message_id: messageId },
  });
}

export async function listEvidence(token: string, reportId: string): Promise<EvidenceAttachmentItem[]> {
  return apiRequest<EvidenceAttachmentItem[]>(`/moderator/reports/${reportId}/evidence`, {
    method: 'GET',
    token,
  });
}

export function getEvidenceDownloadUrl(reportId: string, evidenceId: string): string {
  return `/api/v1/moderator/reports/${reportId}/evidence/${evidenceId}`;
}

export function getArchiveExportUrl(reportId: string): string {
  return `/api/v1/moderator/reports/${reportId}/export`;
}

export async function verifyAuditChain(
  token: string,
  reportId: string
): Promise<{ status: string; is_valid: boolean; chain_length: number; genesis_hash: string; terminal_hash: string }> {
  return apiRequest(`/moderator/reports/${reportId}/audit/verify`, {
    method: 'POST',
    token,
  });
}

export async function rewrapKeys(
  token: string,
  reportId: string
): Promise<{ status: string; new_key_version: number }> {
  return apiRequest(`/moderator/reports/${reportId}/rewrap-keys`, {
    method: 'POST',
    token,
  });
}

export async function listQuorumProposals(token: string): Promise<QuorumProposal[]> {
  return apiRequest<QuorumProposal[]>('/moderator/quorum', {
    method: 'GET',
    token,
  });
}

export async function proposeQuorum(
  token: string,
  data: { action_type: string; target_entity_type: string; target_entity_id?: string; parameters: Record<string, unknown> }
): Promise<QuorumProposal> {
  return apiRequest<QuorumProposal>('/moderator/quorum', {
    method: 'POST',
    token,
    body: data,
  });
}

export async function approveQuorum(
  token: string,
  proposalId: string,
  totpCode: string
): Promise<{ status: string; proposal_id: string; executed_at: string }> {
  return apiRequest(`/moderator/quorum/${proposalId}/approve`, {
    method: 'POST',
    token,
    body: { totp_code: totpCode },
  });
}

export async function rejectQuorum(
  token: string,
  proposalId: string,
  reason: string
): Promise<{ status: string; proposal_id: string }> {
  return apiRequest(`/moderator/quorum/${proposalId}/reject`, {
    method: 'POST',
    token,
    body: { reason },
  });
}

export async function listWebhooks(token: string): Promise<WebhookEndpointItem[]> {
  return apiRequest<WebhookEndpointItem[]>('/moderator/webhooks', {
    method: 'GET',
    token,
  });
}

export async function createWebhook(
  token: string,
  data: { url: string; description?: string; subscribed_events: string[] }
): Promise<{ endpoint_id: string; url: string; secret: string }> {
  return apiRequest('/moderator/webhooks', {
    method: 'POST',
    token,
    body: data,
  });
}

export async function deleteWebhook(token: string, webhookId: string): Promise<{ status: string }> {
  return apiRequest(`/moderator/webhooks/${webhookId}`, {
    method: 'DELETE',
    token,
  });
}

export async function getSecurityState(token: string): Promise<SecurityStateResponse> {
  return apiRequest<SecurityStateResponse>('/moderator/security/state', {
    method: 'GET',
    token,
  });
}

export async function adminCheckIn(
  token: string,
  totpCode: string
): Promise<{ status: string; next_due_at: string }> {
  return apiRequest('/moderator/security/check-in', {
    method: 'POST',
    token,
    body: { totp_code: totpCode },
  });
}

export async function emergencySeal(
  token: string,
  reason: string
): Promise<{ status: string; sealed_at: string }> {
  return apiRequest('/moderator/security/emergency-seal', {
    method: 'POST',
    token,
    body: { reason },
  });
}

export async function emergencyUnseal(token: string): Promise<{ status: string }> {
  return apiRequest('/moderator/security/emergency-unseal', {
    method: 'POST',
    token,
  });
}
