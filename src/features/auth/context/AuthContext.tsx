// Local: src/features/auth/context/AuthContext.tsx

import React, { createContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { AuthState, LoginCredentials, SignUpCredentials, UserProfile } from '../types';
// Remova: import { baserow } from '../../../shared/services/baserowClient'; // REMOVA esta linha
// Remova: import bcrypt from 'bcryptjs'; // REMOVA esta linha

// Remova: const USERS_TABLE_ID = '711'; // REMOVA esta linha
// Remova: const SALT_ROUNDS = 10; // REMOVA esta linha

interface AuthContextType extends AuthState {
  error: string | null;
  signUp: (credentials: SignUpCredentials) => Promise<UserProfile | null>;
  signIn: (credentials: LoginCredentials) => Promise<boolean>;
  signOut: () => void;
  updateProfile: (newProfileData: Partial<UserProfile>) => void;
  refetchProfile: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [authState, setAuthState] = useState<AuthState>({
    profile: null,
    isAuthenticated: false,
    isLoading: true,
  });
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    try {
      const storedUser = localStorage.getItem('userProfile');
      if (storedUser) {
        setAuthState({
          profile: JSON.parse(storedUser),
          isAuthenticated: true,
          isLoading: false,
        });
      } else {
        setAuthState(prev => ({ ...prev, isLoading: false }));
      }
    } catch (error) {
      console.error("Falha ao carregar perfil do localStorage", error);
      setAuthState(prev => ({ ...prev, isLoading: false }));
    }
  }, []);

  const updateProfile = (newProfileData: Partial<UserProfile>) => {
    setAuthState(prev => {
        if (!prev.profile) return prev;
        const updatedProfile = { ...prev.profile, ...newProfileData };
        localStorage.setItem('userProfile', JSON.stringify(updatedProfile));
        return { ...prev, profile: updatedProfile };
    });
  };

  const refetchProfile = useCallback(async () => {
    if (!authState.profile?.id) {
      console.warn("Tentativa de re-sincronizar perfil sem usuário logado.");
      return;
    }
    try {
      // Chame o backend para buscar o perfil atualizado
      const response = await fetch(`/api/users/${authState.profile.id}`);
      if (!response.ok) {
        throw new Error('Falha ao buscar perfil atualizado.');
      }
      const userProfile: UserProfile = await response.json();
      
      localStorage.setItem('userProfile', JSON.stringify(userProfile));
      setAuthState(prev => ({ ...prev, profile: userProfile }));
    } catch (error) {
      console.error("Erro ao re-sincronizar o perfil do usuário:", error);
    }
  }, [authState.profile?.id]);

  const signUp = async (credentials: SignUpCredentials): Promise<UserProfile | null> => {
    setAuthError(null);
    setAuthState(prev => ({ ...prev, isLoading: true }));
    try {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Erro ao cadastrar. Tente novamente.');
      }
      
      const userProfile: UserProfile = data.user;
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return userProfile;

    } catch (error: any) {
      setAuthError(error.message || 'Ocorreu um erro ao cadastrar. Tente novamente.');
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return null;
    }
  };

  const signIn = async (credentials: LoginCredentials): Promise<boolean> => {
    setAuthError(null);
    setAuthState(prev => ({ ...prev, isLoading: true }));
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Falha no login. Verifique suas credenciais.');
      }
      
      const userProfile: UserProfile = data.user;
      localStorage.setItem('userProfile', JSON.stringify(userProfile));
      setAuthState({ profile: userProfile, isAuthenticated: true, isLoading: false });
      return true;

    } catch (error: any) {
      setAuthError(error.message || 'Ocorreu um erro ao fazer login. Tente novamente.');
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return false;
    }
  };

  const signOut = () => {
    localStorage.clear();
    setAuthState({ profile: null, isAuthenticated: false, isLoading: false });
  };

  const value = {
    ...authState,
    error: authError,
    signUp,
    signIn,
    signOut,
    updateProfile,
    refetchProfile,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};