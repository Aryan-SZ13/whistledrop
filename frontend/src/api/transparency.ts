import { apiRequest } from './client';
import type {
  InclusionProofResponse,
  SignedTreeHeadResponse,
  WarrantCanaryResponse,
} from '../types';

export async function getLatestSTH(): Promise<SignedTreeHeadResponse> {
  return apiRequest<SignedTreeHeadResponse>('/transparency/sth', {
    method: 'GET',
  });
}

export async function getInclusionProof(
  leafIndex: number,
  treeSize: number
): Promise<InclusionProofResponse> {
  const query = new URLSearchParams({
    leaf_index: leafIndex.toString(),
    tree_size: treeSize.toString(),
  });
  return apiRequest<InclusionProofResponse>(`/transparency/proof/inclusion?${query.toString()}`, {
    method: 'GET',
  });
}

export async function getConsistencyProof(
  first: number,
  second: number
): Promise<{ first: number; second: number; consistency_path: string[] }> {
  const query = new URLSearchParams({
    first: first.toString(),
    second: second.toString(),
  });
  return apiRequest(`/transparency/proof/consistency?${query.toString()}`, {
    method: 'GET',
  });
}

export async function getLatestCanary(): Promise<WarrantCanaryResponse> {
  return apiRequest<WarrantCanaryResponse>('/canary/latest', {
    method: 'GET',
  });
}

export async function getCanaryHistory(): Promise<WarrantCanaryResponse[]> {
  return apiRequest<WarrantCanaryResponse[]>('/canary/history', {
    method: 'GET',
  });
}
