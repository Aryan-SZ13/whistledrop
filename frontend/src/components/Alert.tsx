import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle, Info } from 'lucide-react';

interface AlertProps {
  type?: 'info' | 'warning' | 'danger' | 'success';
  title?: string;
  children: React.ReactNode;
}

export const Alert: React.FC<AlertProps> = ({ type = 'info', title, children }) => {
  const getIcon = () => {
    switch (type) {
      case 'warning':
        return <AlertTriangle size={18} color="#f59e0b" style={{ flexShrink: 0, marginTop: 1 }} />;
      case 'danger':
        return <AlertCircle size={18} color="#ef4444" style={{ flexShrink: 0, marginTop: 1 }} />;
      case 'success':
        return <CheckCircle size={18} color="#10b981" style={{ flexShrink: 0, marginTop: 1 }} />;
      case 'info':
      default:
        return <Info size={18} color="#38bdf8" style={{ flexShrink: 0, marginTop: 1 }} />;
    }
  };

  return (
    <div className={`alert alert-${type}`}>
      {getIcon()}
      <div style={{ flex: 1 }}>
        {title && <div style={{ fontWeight: 600, marginBottom: '0.2rem' }}>{title}</div>}
        <div>{children}</div>
      </div>
    </div>
  );
};
