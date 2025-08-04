import React from 'react';
import LoginForm from './LoginForm';
const LoginPage = ({ onLogin, onNavigateSignUp, isLoading, error }) => {
    return (<div className="min-h-screen flex items-center justify-center bg-gray-50 px-4 fade-in">
      <div className="max-w-md w-full space-y-8 bg-white p-10 rounded-xl shadow-md">
        <div>
          <h2 className="text-center text-3xl font-bold text-gray-900">
            Recruta.<span className="text-indigo-600">AI</span>
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Faça login na sua conta para começar
          </p>
        </div>
        
        {error && (<div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-md text-sm" role="alert">
                <p>{error}</p>
            </div>)}

        <LoginForm onSubmit={onLogin} isLoading={isLoading}/>
        
        <div className="text-sm text-center">
            <button onClick={onNavigateSignUp} className="font-medium text-indigo-600 hover:text-indigo-500">
              Não tem uma conta? Crie agora
            </button>
        </div>
      </div>
    </div>);
};
export default LoginPage;
