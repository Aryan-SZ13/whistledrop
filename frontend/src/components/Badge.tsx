import React from 'react';
import type { ReportPriority, ReportStatus } from '../types';

export const StatusBadge: React.FC<{ status: ReportStatus }> = ({ status }) => {
  const normalized = status.toLowerCase();
  const label = status.replace('_', ' ');
  return <span className={`badge badge-${normalized}`}>{label}</span>;
};

export const PriorityBadge: React.FC<{ priority: ReportPriority }> = ({ priority }) => {
  const normalized = priority.toLowerCase();
  return <span className={`badge badge-${normalized}`}>{priority}</span>;
};
