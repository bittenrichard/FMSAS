import React, { useState } from 'react';
// --- IMPORTAÇÃO DO NOVO COMPONENTE ---
import PhoneInput from 'react-phone-input-2';
const SignUpForm = ({ onSubmit, isLoading = false }) => {
    const [name, setName] = useState('');
    const [company, setCompany] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [telefone, setTelefone] = useState('');
    const handleSubmit = (e) => {
        e.preventDefault();
        onSubmit({ nome: name, empresa: company, email, password, telefone });
    };
    return (<form className="mt-8 space-y-6" onSubmit={handleSubmit}>
      <div className="rounded-md shadow-sm space-y-4">
        <div>
          <label htmlFor="name" className="sr-only">Nome Completo</label>
          <input id="name" name="name" type="text" autoComplete="name" required className="appearance-none relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Nome completo" value={name} onChange={(e) => setName(e.target.value)} disabled={isLoading}/>
        </div>
        <div>
          <label htmlFor="company" className="sr-only">Empresa</label>
          <input id="company" name="company" type="text" autoComplete="organization" required className="appearance-none relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Nome da sua empresa" value={company} onChange={(e) => setCompany(e.target.value)} disabled={isLoading}/>
        </div>
        
        {/* --- CAMPO DE TELEFONE SUBSTITUÍDO PELO COMPONENTE INTELIGENTE --- */}
        <div>
          <label htmlFor="telefone" className="sr-only">Telefone</label>
          <PhoneInput country={'br'} // Define o Brasil como país padrão
     value={telefone} onChange={setTelefone} inputProps={{
            name: 'telefone',
            required: true,
        }} inputClass="!w-full !py-3 !px-3 !border !border-gray-300 !rounded-md focus:!ring-indigo-500 focus:!border-indigo-500 sm:!text-sm" containerClass="w-full" buttonClass="!border !border-gray-300 !rounded-l-md !bg-gray-50" dropdownClass="!rounded-md" placeholder="Seu telefone (WhatsApp)" disabled={isLoading}/>
        </div>
        {/* --- FIM DA SUBSTITUIÇÃO --- */}
        
        <div>
          <label htmlFor="email-address" className="sr-only">Email</label>
          <input id="email-address" name="email" type="email" autoComplete="email" required className="appearance-none relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="seu@email.com" value={email} onChange={(e) => setEmail(e.target.value)} disabled={isLoading}/>
        </div>
        <div>
          <label htmlFor="password" className="sr-only">Senha</label>
          <input id="password" name="password" type="password" autoComplete="new-password" required minLength={6} className="appearance-none relative block w-full px-3 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Senha (mínimo 6 caracteres)" value={password} onChange={(e) => setPassword(e.target.value)} disabled={isLoading}/>
        </div>
      </div>

      <div>
        <button type="submit" disabled={isLoading} className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
          {isLoading ? 'Criando conta...' : 'Criar Conta'}
        </button>
      </div>
    </form>);
};
export default SignUpForm;
