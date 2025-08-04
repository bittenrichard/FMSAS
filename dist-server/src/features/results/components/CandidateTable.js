import React from 'react';
import { MessageCircle, Eye, ChevronsUpDown, ArrowDown, ArrowUp, Loader2 } from 'lucide-react';
import { formatPhoneNumberForWhatsApp } from '../../../shared/utils/formatters';
const CandidateTable = ({ candidates, onViewDetails, isLoading = false, requestSort, sortConfig }) => {
    const getScoreColor = (score) => {
        if (score >= 85)
            return 'text-green-600';
        if (score >= 70)
            return 'text-yellow-600';
        return 'text-red-600';
    };
    const getScoreBarColor = (score) => {
        if (score >= 85)
            return 'bg-green-500';
        if (score >= 70)
            return 'bg-yellow-500';
        return 'bg-red-500';
    };
    const getSortIcon = (key) => {
        if (sortConfig.key !== key) {
            return <ChevronsUpDown size={14} className="ml-1 text-gray-400"/>;
        }
        if (sortConfig.direction === 'ascending') {
            return <ArrowUp size={14} className="ml-1 text-indigo-600"/>;
        }
        return <ArrowDown size={14} className="ml-1 text-indigo-600"/>;
    };
    return (<div className="bg-white p-6 rounded-lg shadow-sm">
      <h3 className="text-lg font-semibold mb-4">Histórico de Candidatos Analisados</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="text-xs text-gray-500 uppercase border-b">
              <th className="px-4 py-3 font-semibold">
                <button onClick={() => requestSort('nome')} className="flex items-center text-left hover:text-gray-900 transition-colors">
                  Candidato {getSortIcon('nome')}
                </button>
              </th>
              <th className="px-4 py-3 font-semibold">
                <button onClick={() => requestSort('score')} className="flex items-center text-left hover:text-gray-900 transition-colors">
                  Score {getSortIcon('score')}
                </button>
              </th>
              <th className="px-4 py-3 font-semibold">Resumo da IA</th>
              <th className="px-4 py-3 font-semibold text-center">Ações</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (<tr>
                <td colSpan={4} className="text-center py-10 text-gray-500">
                  <Loader2 className="mx-auto h-8 w-8 text-indigo-600 animate-spin"/>
                  <p className="mt-2">Carregando candidatos...</p>
                </td>
              </tr>) : candidates.length === 0 ? (<tr>
                <td colSpan={4} className="text-center py-10 text-gray-500">
                  Nenhum candidato encontrado para esta vaga.
                </td>
              </tr>) : (candidates.map((candidate) => {
            const whatsappNumber = formatPhoneNumberForWhatsApp(candidate.telefone);
            return (<tr key={candidate.id} className="border-b hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-4 font-medium">{candidate.nome}</td>
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        <span className={`font-bold mr-2 ${getScoreColor(candidate.score || 0)}`}>
                          {candidate.score || 0}%
                        </span>
                        <div className="w-20 bg-gray-200 rounded-full h-2">
                          <div className={`h-2 rounded-full ${getScoreBarColor(candidate.score || 0)}`} style={{ width: `${candidate.score || 0}%` }}/>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-600 max-w-sm">
                      {candidate.resumo_ia || 'N/A'}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center justify-center space-x-2">
                         <button onClick={() => onViewDetails(candidate)} className="p-2 text-gray-500 hover:bg-gray-200 hover:text-indigo-600 rounded-full transition-colors" title="Ver Detalhes">
                          <Eye size={18}/>
                        </button>
                        <a href={whatsappNumber ? `https://wa.me/${whatsappNumber}` : undefined} target="_blank" rel="noopener noreferrer" onClick={(e) => !whatsappNumber && e.preventDefault()} className={`p-2 rounded-full transition-colors ${!whatsappNumber
                    ? 'text-gray-300 cursor-not-allowed'
                    : 'text-gray-500 hover:bg-green-100 hover:text-green-600'}`} title={whatsappNumber ? 'Chamar no WhatsApp' : 'Telefone não disponível'}>
                          <MessageCircle size={18}/>
                        </a>
                      </div>
                    </td>
                  </tr>);
        }))}
          </tbody>
        </table>
      </div>
    </div>);
};
export default CandidateTable;
