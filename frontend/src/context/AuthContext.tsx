import React, { createContext, useContext, useState } from 'react';
import { logout as apiLogout } from '../api/moderator';

interface AuthContextType {
  token: string | null;
  refreshTokenVal: string | null;
  isAuthenticated: boolean;
  setAuthTokens: (accessToken: string, refreshToken?: string) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(null);
  const [refreshTokenVal, setRefreshTokenVal] = useState<string | null>(null);

  const setAuthTokens = (accessToken: string, newRefreshToken?: string) => {
    setToken(accessToken);
    if (newRefreshToken) {
      setRefreshTokenVal(newRefreshToken);
    }
  };

  const logout = async () => {
    if (token) {
      try {
        await apiLogout(token);
      } catch {
        // Ignore network failure during logout
      }
    }
    setToken(null);
    setRefreshTokenVal(null);
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        refreshTokenVal,
        isAuthenticated: Boolean(token),
        setAuthTokens,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
