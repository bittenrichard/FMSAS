import React from 'react';
import SignUpForm from './SignUpForm';
import { SignUpCredentials } from '../types';

interface SignUpPageProps {
  onSignUp: (credentials: SignUpCredentials) => void;
  onNavigateLogin: () => void;
  isLoading?: boolean;
  error?: string | null;
}

const SignUpPage: React.FC<SignUpPageProps> = ({ onSignUp, onNavigateLogin, isLoading, error }) => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4 fade-in">
      <div className="max-w-md w-full space-y-8 bg-white p-10 rounded-xl shadow-md">
        <div>
          <h2 className="text-center text-3xl font-bold text-gray-900">
            Crie sua conta
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            E comece a otimizar suas contratações com IA.
          </p>
        </div>
        
        {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-md text-sm" role="alert">
                <p>{error}</p>
            </div>
        )}

        <SignUpForm onSubmit={onSignUp} isLoading={isLoading} />

        <div className="text-sm text-center">
            <button onClick={onNavigateLogin} className="font-medium text-indigo-600 hover:text-indigo-500">
              Já tem uma conta? Faça login
            </button>
        </div>
      </div>
    </div>
  );
};

export default SignUpPage;