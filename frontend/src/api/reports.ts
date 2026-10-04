import { apiRequest } from './client';
import type {
  ReportCreateRequest,
  ReportCreateResponse,
  VerificationReceiptResponse,
} from '../types';

export async function submitReport(data: ReportCreateRequest): Promise<ReportCreateResponse> {
  return apiRequest<ReportCreateResponse>('/reports', {
    method: 'POST',
    body: data,
  });
}

export async function uploadEvidence(
  caseCode: string,
  file: File
): Promise<{ status: string; attachment_id: string; scan_status: string }> {
  const formData = new FormData();
  formData.append('file', file);

  // Invariant: Authenticate via X-Case-Code header, never in URL
  return apiRequest('/reports/evidence', {
    method: 'POST',
    caseCode,
    body: formData,
  });
}


export async function getVerificationReceipt(caseCode: string): Promise<VerificationReceiptResponse> {
  return apiRequest<VerificationReceiptResponse>('/reports/verification', {
    method: 'GET',
    caseCode,
  });
}

export async function withdrawReport(
  caseCode: string,
  reason: string = 'User requested withdrawal'
): Promise<{ status: string; message: string; shredded_at: string }> {
  return apiRequest('/reports/withdraw', {
    method: 'POST',
    caseCode,
    body: { reason },
  });
}
