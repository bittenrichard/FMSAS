import React from 'react';
import { PlusCircle } from 'lucide-react';
const WelcomeEmptyState = ({ onNewScreening }) => {
    return (<div className="text-center bg-white p-10 rounded-lg shadow-sm border border-gray-100 mt-8">
      <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-indigo-100">
        <PlusCircle className="h-6 w-6 text-indigo-600" aria-hidden="true"/>
      </div>
      <h3 className="mt-5 text-2xl font-semibold text-gray-900">
        Bem-vindo(a) ao Recruta.AI!
      </h3>
      <p className="mt-2 text-md text-gray-500 max-w-md mx-auto">
        Parece que você ainda não criou nenhuma triagem de vaga. Que tal começar agora e deixar a nossa IA trabalhar para você?
      </p>
      <div className="mt-6">
        <button type="button" onClick={onNewScreening} className="inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors">
          <PlusCircle className="-ml-1 mr-3 h-5 w-5" aria-hidden="true"/>
          Criar sua Primeira Triagem
        </button>
      </div>
    </div>);
};
export default WelcomeEmptyState;
