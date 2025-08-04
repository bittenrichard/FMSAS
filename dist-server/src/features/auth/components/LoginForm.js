import React, { useState } from 'react';
const LoginForm = ({ onSubmit, isLoading = false }) => {
    // --- AQUI ESTÁ A MUDANÇA ---
    // Trocamos os valores fixos por strings vazias para iniciar os campos limpos.
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const handleSubmit = (e) => {
        e.preventDefault();
        onSubmit({ email, password });
    };
    return (<form className="mt-8 space-y-6" onSubmit={handleSubmit}>
      <div className="rounded-md shadow-sm -space-y-px">
        <div>
          <label htmlFor="email-address" className="sr-only">
            Email
          </label>
          <input id="email-address" name="email" type="email" autoComplete="email" required className="appearance-none rounded-none relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm" placeholder="seu@email.com" value={email} onChange={(e) => setEmail(e.target.value)} disabled={isLoading}/>
        </div>
        <div>
          <label htmlFor="password" className="sr-only">
            Senha
          </label>
          <input id="password" name="password" type="password" autoComplete="current-password" required className="appearance-none rounded-none relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm" placeholder="Sua senha" value={password} onChange={(e) => setPassword(e.target.value)} disabled={isLoading}/>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <div className="text-sm">
          <a href="#" className="font-medium text-indigo-600 hover:text-indigo-500">
            Esqueceu sua senha?
          </a>
        </div>
      </div>

      <div>
        <button type="submit" disabled={isLoading} className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
          {isLoading ? 'Entrando...' : 'Entrar'}
        </button>
      </div>
    </form>);
};
export default LoginForm;
