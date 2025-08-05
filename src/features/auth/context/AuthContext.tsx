import { createContext, useState, useEffect, ReactNode } from 'react';
import { User, AuthContextType, SignInCredentials, SignUpCredentials } from '../types';
import { translateAuthError } from '../utils/errorTranslator';

// A URL base da API é lida da variável de ambiente injetada pelo Vite
const API_URL = import.meta.env.VITE_API_BASE_URL;

export const AuthContext = createContext<AuthContextType | null>(null);

interface AuthProviderProps {
    children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const verifyUser = async () => {
            const token = localStorage.getItem('token');
            if (token) {
                try {
                    const response = await fetch(`${API_URL}/api/auth/me`, {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });

                    if (response.ok) {
                        const data: User = await response.json();
                        setUser(data);
                    } else {
                        localStorage.removeItem('token');
                        setUser(null);
                    }
                } catch (err) {
                    localStorage.removeItem('token');
                    setUser(null);
                }
            }
            setLoading(false);
        };

        verifyUser();
    }, []);

    const signIn = async (credentials: SignInCredentials) => {
        setLoading(true);
        setError(null);
        try {
            const response = await fetch(`${API_URL}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Falha no login');
            }

            const data = await response.json();
            localStorage.setItem('token', data.token);
            setUser(data.user);
        } catch (err: any) {
            setError(translateAuthError(err.message));
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const signUp = async (credentials: SignUpCredentials) => {
        setLoading(true);
        setError(null);
        try {
            const response = await fetch(`${API_URL}/api/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Falha no registro');
            }

            const data = await response.json();
            localStorage.setItem('token', data.token);
            setUser(data.user);
        } catch (err: any) {
            setError(translateAuthError(err.message));
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const signOut = () => {
        localStorage.removeItem('token');
        setUser(null);
    };

    const updateUser = (updatedUser: Partial<User>) => {
        if (user) {
            setUser({ ...user, ...updatedUser });
        }
    };

    return (
        <AuthContext.Provider value={{ user, loading, error, signIn, signUp, signOut, updateUser }}>
            {children}
        </AuthContext.Provider>
    );
};