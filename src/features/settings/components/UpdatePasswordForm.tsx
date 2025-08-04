import React, { useState } from 'react';
import { CheckCircle, AlertCircle } from 'lucide-react';
import { useAuth } from '../../auth/hooks/useAuth';
// Remova: import { baserow } from '../../../shared/services/baserowClient'; // REMOVA esta linha
// Remova: import bcrypt from 'bcryptjs'; // REMOVA esta linha

// Remova: const USERS_TABLE_ID = '711'; // REMOVA esta linha
// Remova: const SALT_ROUNDS = 10; // REMOVA esta linha

const UpdatePasswordForm = () => {
    const { profile } = useAuth();
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [successMessage, setSuccessMessage] = useState<string | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSuccessMessage(null);
        setErrorMessage(null);

        if (!profile) {
            setErrorMessage('Usuário não encontrado. Por favor, faça login novamente.');
            return;
        }

        if (password.length < 6) {
            setErrorMessage('A nova senha deve ter no mínimo 6 caracteres.');
            return;
        }
        if (password !== confirmPassword) {
            setErrorMessage('As senhas não coincidem.');
            return;
        }

        setLoading(true);
        try {
            // Chame o backend para atualizar a senha
            const response = await fetch(`/api/users/${profile.id}/password`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Não foi possível atualizar a senha. Tente novamente.');
            }

            setSuccessMessage('Senha atualizada com sucesso!');
            setPassword('');
            setConfirmPassword('');
        } catch (error: any) {
            setErrorMessage(error.message || 'Não foi possível atualizar a senha. Tente novamente.');
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="bg-white p-8 rounded-lg shadow-sm border border-gray-100 mt-8">
            <h3 className="text-xl font-semibold mb-6 text-gray-800">Alterar Senha</h3>

            {successMessage && (
                <div className="mb-4 flex items-center gap-2 rounded-md bg-green-50 p-3 text-sm text-green-700">
                    <CheckCircle size={18} /> {successMessage}
                </div>
            )}
            {errorMessage && (
                <div className="mb-4 flex items-center gap-2 rounded-md bg-red-50 p-3 text-sm text-red-700">
                    <AlertCircle size={18} /> {errorMessage}
                </div>
            )}
            
            <form onSubmit={handlePasswordSubmit} className="space-y-6">
                <div>
                    <label htmlFor="new-password" className="block text-sm font-medium text-gray-700">Nova Senha</label>
                    <input
                        id="new-password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        placeholder="••••••••"
                        required
                    />
                </div>
                <div>
                    <label htmlFor="confirm-password" className="block text-sm font-medium text-gray-700">Confirmar Nova Senha</label>
                    <input
                        id="confirm-password"
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        placeholder="••••••••"
                        required
                    />
                </div>
                <div className="flex justify-end pt-2">
                    <button type="submit" disabled={loading} className="px-6 py-2 bg-indigo-600 text-white font-semibold rounded-md hover:bg-indigo-700 transition-colors disabled:opacity-50">
                        {loading ? 'Salvando...' : 'Alterar Senha'}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default UpdatePasswordForm;