export type ReportCategory =
  | 'FINANCIAL_MISCONDUCT'
  | 'CORRUPTION_BRIBERY'
  | 'SAFETY_HEALTH_VIOLATION'
  | 'ENVIRONMENTAL_DAMAGE'
  | 'DATA_PRIVACY_BREACH'
  | 'HARASSMENT_DISCRIMINATION'
  | 'OTHER';

export type ReportStatus = 'SUBMITTED' | 'UNDER_REVIEW' | 'RESOLVED' | 'DISMISSED';

export type ReportPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ModeratorRole = 'MODERATOR' | 'ADMIN';

export type ReportUpdateType = 'PUBLIC_UPDATE' | 'INTERNAL_NOTE';

export type EvidenceScanStatus =
  | 'PENDING_SCAN'
  | 'SCAN_CLEAN'
  | 'INFECTED'
  | 'SCAN_FAILED'
  | 'PROMOTING'
  | 'CLEAN'
  | 'DELETED';

export interface ReportCreateRequest {
  title: string;
  description: string;
  category: ReportCategory;
}

export interface ReportCreateResponse {
  case_code: string;
  status: ReportStatus;
  created_at: string;
}

export interface ReportUpdatePublic {
  message: string;
  created_at: string;
}

export interface ReportTrackingResponse {
  status: ReportStatus;
  updates: ReportUpdatePublic[];
}

export interface CaseMessagePublic {
  id: string;
  sender_type: 'REPORTER' | 'MODERATOR';
  content: string;
  created_at: string;
}

export interface CaseMessageListResponse {
  items: CaseMessagePublic[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface NotificationStatusResponse {
  status_version: number;
  status: ReportStatus;
  unread_messages_count: number;
  last_notified_at: string;
}

export interface VerificationReceiptResponse {
  case_reference: string;
  status: ReportStatus;
  created_at: string;
  resolved_at: string | null;
  withdrawn_at: string | null;
  evidence_count: number;
  status_updates_count: number;
  key_id: string;
  signature: string;
}

export interface SignedTreeHeadResponse {
  tree_size: number;
  root_hash: string;
  timestamp: string;
  signature: string;
  signing_key_id: string;
}

export interface InclusionProofResponse {
  leaf_index: number;
  tree_size: number;
  leaf_hash: string;
  audit_path: string[];
}

export interface WarrantCanaryResponse {
  statement_serial: number;
  statement_text: string;
  statement_hash: string;
  issued_at: string;
  valid_until: string;
  signature: string;
  signing_key_id: string;
  status: string;
  is_active: boolean;
}

export interface SecurityStateResponse {
  is_sealed: boolean;
  sealed_at: string | null;
  seal_reason: string | null;
  dead_man_due_at: string | null;
  dead_man_warning_due_at: string | null;
  last_admin_check_in_at: string | null;
  status: string;
}

export interface LoginResponse {
  requires_mfa: boolean;
  challenge_ticket?: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
}

export interface MFASetupResponse {
  otpauth_url: string;
  secret: string;
}

export interface ModeratorReportListItem {
  id: string;
  title: string;
  category: ReportCategory;
  status: ReportStatus;
  priority: ReportPriority;
  assigned_to_id: string | null;
  created_at: string;
  updated_at: string;
  version_id: number;
}

export interface ModeratorReportListResponse {
  items: ModeratorReportListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface ModeratorReportDetail {
  id: string;
  title: string;
  description: string;
  category: ReportCategory;
  status: ReportStatus;
  priority: ReportPriority;
  assigned_to_id: string | null;
  created_at: string;
  updated_at: string;
  version_id: number;
  updates: Array<{
    id: string;
    type: ReportUpdateType;
    message: string;
    moderator_id: string;
    created_at: string;
  }>;
}

export interface EvidenceAttachmentItem {
  id: string;
  storage_key: string;
  scan_status: EvidenceScanStatus;
  content_type: string;
  file_size_bytes: number;
  sha256_hash: string;
  created_at: string;
}

export interface TimelineEventItem {
  event_id: string;
  event_type: string;
  event_timestamp: string;
  summary: string;
  metadata?: Record<string, unknown>;
}

export interface DashboardStats {
  total_reports: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
  unassigned_reports: number;
  my_active_cases: number;
}

export interface QuorumProposal {
  id: string;
  action_type: string;
  target_entity_type: string;
  target_entity_id: string | null;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'EXECUTED' | 'FAILED_CONFLICT';
  proposed_by_id: string;
  approved_by_id: string | null;
  parameters: Record<string, unknown>;
  created_at: string;
  expires_at: string;
}

export interface WebhookEndpointItem {
  id: string;
  url: string;
  description: string | null;
  is_active: boolean;
  subscribed_events: string[];
  failure_count: number;
  created_at: string;
}
