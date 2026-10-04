import { apiRequest } from './client';
import type {
  CaseMessageListResponse,
  CaseMessagePublic,
  NotificationStatusResponse,
} from '../types';

export async function listMessages(
  caseCode: string,
  cursor: string | null = null,
  limit: number = 50
): Promise<CaseMessageListResponse> {
  const query = new URLSearchParams();
  if (cursor) query.set('cursor', cursor);
  query.set('limit', limit.toString());

  return apiRequest<CaseMessageListResponse>(`/reports/messages?${query.toString()}`, {
    method: 'GET',
    caseCode,
  });
}

export async function sendMessage(
  caseCode: string,
  content: string,
  idempotencyKey?: string
): Promise<CaseMessagePublic> {
  return apiRequest<CaseMessagePublic>('/reports/messages', {
    method: 'POST',
    caseCode,
    idempotencyKey: idempotencyKey || crypto.randomUUID(),
    body: { content },
  });
}

export async function acknowledgeMessageRead(
  caseCode: string,
  messageId: string
): Promise<{ status: string }> {
  return apiRequest('/reports/messages/read', {
    method: 'POST',
    caseCode,
    body: { message_id: messageId },
  });
}

export async function getNotifications(caseCode: string): Promise<NotificationStatusResponse> {
  return apiRequest<NotificationStatusResponse>('/reports/notifications', {
    method: 'GET',
    caseCode,
  });
}

export async function acknowledgeNotificationRead(
  caseCode: string,
  acknowledgedStatusVersion: number
): Promise<{ status: string }> {
  return apiRequest('/reports/notifications/read', {
    method: 'POST',
    caseCode,
    body: { acknowledged_status_version: acknowledgedStatusVersion },
  });
}
