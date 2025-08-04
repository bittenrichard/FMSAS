// Local: src/features/dashboard/components/RecentScreenings.tsx

import React from 'react';
import { Trash2, Eye, Search, Plus, FilePenLine } from 'lucide-react'; // Importamos o ícone de edição
import { JobPosting } from '../../screening/types';
import WelcomeEmptyState from './WelcomeEmptyState';

interface RecentScreeningsProps {
  jobs: JobPosting[];
  onViewResults: (job: JobPosting) => void;
  onOpenDeleteModal: (job: JobPosting) => void;
  onEditJob: (job: JobPosting) => void; // <-- NOVA PROP PARA EDIÇÃO
  onNewScreening: () => void;
  searchTerm: string;
  setSearchTerm: (term: string) => void;
}

const RecentScreenings: React.FC<RecentScreeningsProps> = ({
  jobs,
  onViewResults,
  onOpenDeleteModal,
  onEditJob, // <-- NOVA PROP PARA EDIÇÃO
  onNewScreening,
  searchTerm,
  setSearchTerm,
}) => {
  const showWelcomeState = jobs.length === 0 && searchTerm === '';

  if (showWelcomeState) {
    return <WelcomeEmptyState onNewScreening={onNewScreening} />;
  }

  return (
    <div className="mt-8 bg-white p-6 rounded-lg shadow-sm border border-gray-100">
      <div className="flex flex-col md:flex-row justify-between items-center mb-6 gap-4">
        <h3 className="text-xl font-bold text-gray-800">Triagens</h3>
        <div className="flex flex-col md:flex-row items-center gap-3 w-full md:w-auto">
          <div className="relative w-full md:w-auto">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={20} />
            <input
              type="text"
              placeholder="Filtrar por vaga..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
          <button
            onClick={onNewScreening}
            className="flex items-center justify-center gap-2 w-full md:w-auto px-4 py-2 bg-indigo-600 text-white font-semibold rounded-md hover:bg-indigo-700 transition-colors"
          >
            <Plus size={18} />
            Criar Triagem
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="text-xs text-gray-500 uppercase border-b bg-gray-50">
              <th className="px-4 py-3 font-semibold">Vaga</th>
              <th className="px-4 py-3 font-semibold">Candidatos</th>
              <th className="px-4 py-3 font-semibold">Score Médio</th>
              <th className="px-4 py-3 font-semibold text-center">Ações</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => (
              <tr key={job.id} className="border-b hover:bg-gray-50 transition-colors">
                <td className="px-4 py-4 font-medium text-gray-800">{job.titulo}</td>
                <td className="px-4 py-4 text-gray-600 font-bold">{job.candidateCount}</td>
                <td className="px-4 py-4 text-green-600 font-bold">{job.averageScore}%</td>
                <td className="px-4 py-4">
                  <div className="flex items-center justify-center space-x-3">
                    <button onClick={() => onViewResults(job)} className="text-gray-500 hover:text-indigo-600" title="Ver Resultados">
                      <Eye size={18} />
                    </button>
                    {/* --- BOTÃO DE EDITAR ADICIONADO AQUI --- */}
                    <button onClick={() => onEditJob(job)} className="text-gray-500 hover:text-blue-600" title="Editar Vaga">
                      <FilePenLine size={18} />
                    </button>
                    <button onClick={() => onOpenDeleteModal(job)} className="text-gray-500 hover:text-red-600" title="Excluir Triagem">
                      <Trash2 size={18} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {jobs.length === 0 && searchTerm !== '' && (
          <div className="text-center py-10 text-gray-500">
            Nenhuma triagem encontrada para "{searchTerm}".
          </div>
        )}
      </div>
    </div>
  );
};

export default RecentScreenings;