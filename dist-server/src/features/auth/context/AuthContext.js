// Local: src/features/auth/context/AuthContext.tsx
import React, { createContext, useState, useEffect, useCallback } from 'react';
export const AuthContext = createContext(undefined);
export const AuthProvider = ({ children }) => {
    const [authState, setAuthState] = useState({
        profile: null,
        isAuthenticated: false,
        isLoading: true,
    });
    const [authError, setAuthError] = useState(null);
    useEffect(() => {
        try {
            const storedUser = localStorage.getItem('userProfile');
            if (storedUser) {
                setAuthState({
                    profile: JSON.parse(storedUser),
                    isAuthenticated: true,
                    isLoading: false,
                });
            }
            else {
                setAuthState(prev => ({ ...prev, isLoading: false }));
            }
        }
        catch (error) {
            console.error("Falha ao carregar perfil do localStorage", error);
            setAuthState(prev => ({ ...prev, isLoading: false }));
        }
    }, []);
    const updateProfile = (newProfileData) => {
        setAuthState(prev => {
            if (!prev.profile)
                return prev;
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
            const userProfile = await response.json();
            localStorage.setItem('userProfile', JSON.stringify(userProfile));
            setAuthState(prev => ({ ...prev, profile: userProfile }));
        }
        catch (error) {
            console.error("Erro ao re-sincronizar o perfil do usuário:", error);
        }
    }, [authState.profile?.id]);
    const signUp = async (credentials) => {
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
            const userProfile = data.user;
            setAuthState(prev => ({ ...prev, isLoading: false }));
            return userProfile;
        }
        catch (error) {
            setAuthError(error.message || 'Ocorreu um erro ao cadastrar. Tente novamente.');
            setAuthState(prev => ({ ...prev, isLoading: false }));
            return null;
        }
    };
    const signIn = async (credentials) => {
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
            const userProfile = data.user;
            localStorage.setItem('userProfile', JSON.stringify(userProfile));
            setAuthState({ profile: userProfile, isAuthenticated: true, isLoading: false });
            return true;
        }
        catch (error) {
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
    return (<AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>);
};
