import React from 'react';
import { X, MessageCircle } from 'lucide-react';
import { Candidate } from '../../results/types';
import { formatPhoneNumberForWhatsApp } from '../../../shared/utils/formatters';

interface ApprovedCandidatesModalProps {
  candidates: Candidate[];
  onClose: () => void;
  isLoading: boolean;
}

const ApprovedCandidatesModal: React.FC<ApprovedCandidatesModalProps> = ({ candidates, onClose, isLoading }) => {
  const getScoreColor = (score: number) => {
    if (score >= 95) return 'text-green-600';
    return 'text-blue-600';
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50 p-4 transition-opacity duration-300">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-5xl max-h-[90vh] flex flex-col transform transition-all duration-300 scale-95 opacity-0 animate-scale-in">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-bold text-gray-800">Candidatos Aprovados ({'>'}=90%)</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800 transition-colors">
            <X size={24} />
          </button>
        </div>
        
        <div className="p-6 overflow-y-auto">
          {isLoading ? (
            <p className="text-center py-8">Carregando candidatos...</p>
          ) : candidates.length === 0 ? (
            <p className="text-center text-gray-500 py-8">Nenhum candidato com score acima de 90% encontrado.</p>
          ) : (
            <table className="w-full text-left">
              <thead>
                <tr className="text-xs text-gray-500 uppercase border-b bg-gray-50">
                  <th className="px-4 py-3 font-semibold">Candidato (NOME)</th>
                  <th className="px-4 py-3 font-semibold">Score</th>
                  <th className="px-4 py-3 font-semibold">Vaga (TRIAGEM)</th>
                  <th className="px-4 py-3 font-semibold">Resumo da IA</th>
                  <th className="px-4 py-3 font-semibold text-center">Ações</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((candidate) => {
                  const whatsappNumber = formatPhoneNumberForWhatsApp(candidate.telefone);
                  
                  return (
                    <tr key={candidate.id} className="border-b hover:bg-gray-50 transition-colors">
                      <td className="px-4 py-4 font-medium">{candidate.nome}</td>
                      <td className={`px-4 py-4 font-bold ${getScoreColor(candidate.score || 0)}`}>
                        {candidate.score}%
                      </td>
                      <td className="px-4 py-4 text-gray-600">{candidate.vaga && candidate.vaga[0] ? candidate.vaga[0].value : 'Não informada'}</td>
                      <td className="px-4 py-4 text-sm text-gray-600 max-w-md">
                        {candidate.resumo_ia}
                      </td>
                      <td className="px-4 py-4 text-center">
                        <a
                          href={whatsappNumber ? `https://wa.me/${whatsappNumber}` : undefined}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={`
                            flex items-center justify-center gap-2 w-full px-3 py-2 
                            bg-indigo-600 text-white font-semibold rounded-md 
                            transition-colors
                            ${!whatsappNumber 
                              ? 'opacity-50 cursor-not-allowed' 
                              : 'hover:bg-indigo-700'
                            }
                          `}
                          onClick={(e) => !whatsappNumber && e.preventDefault()}
                          title={whatsappNumber ? 'Chamar no WhatsApp' : 'Telefone não disponível'}
                        >
                          <MessageCircle size={16} />
                          Chamar
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
      <style>{`
        @keyframes scale-in {
          from { transform: scale(0.95); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }
        .animate-scale-in {
          animation: scale-in 0.2s ease-out forwards;
        }
      `}</style>
    </div>
  );
};

export default ApprovedCandidatesModal;