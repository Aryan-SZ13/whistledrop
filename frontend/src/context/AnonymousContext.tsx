import React, { createContext, useContext, useState } from 'react';

interface AnonymousContextType {
  caseCode: string | null;
  setCaseCode: (code: string | null) => void;
  clearCaseCode: () => void;
  hasActiveSession: boolean;
}

const AnonymousContext = createContext<AnonymousContextType | undefined>(undefined);

export const AnonymousProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Invariant: In-memory state only. Never persisted in localStorage, sessionStorage, or URL.
  const [caseCode, setCaseCodeState] = useState<string | null>(null);

  const setCaseCode = (code: string | null) => {
    setCaseCodeState(code ? code.trim() : null);
  };

  const clearCaseCode = () => {
    setCaseCodeState(null);
  };

  return (
    <AnonymousContext.Provider
      value={{
        caseCode,
        setCaseCode,
        clearCaseCode,
        hasActiveSession: Boolean(caseCode),
      }}
    >
      {children}
    </AnonymousContext.Provider>
  );
};

export const useAnonymous = (): AnonymousContextType => {
  const context = useContext(AnonymousContext);
  if (!context) {
    throw new Error('useAnonymous must be used within an AnonymousProvider');
  }
  return context;
};
