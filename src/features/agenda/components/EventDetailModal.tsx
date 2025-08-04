// Local: src/features/agenda/components/EventDetailModal.tsx

import React from 'react';
import { X, User, Briefcase, Calendar, Link as LinkIcon, Info, Download } from 'lucide-react'; // Adicionado o ícone Download
import { CalendarEvent } from '../types';
import { format } from 'date-fns';
import { ptBR } from 'date-fns/locale';

interface EventDetailModalProps {
  event: CalendarEvent | null;
  onClose: () => void;
}

const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  const { resource } = event;
  const candidate = resource.Candidato && resource.Candidato[0];
  const job = resource.Vaga && resource.Vaga[0];
  const googleEventLink = (resource as any).google_event_link; // Acessando o link do evento, se existir
  // NOVO: Acessando o currículo do candidato
  const candidateCurriculum = candidate?.curriculo?.[0]; // Pega o primeiro currículo, se houver

  const formatDate = (date: Date) => {
    return format(date, "EEEE, dd 'de' MMMM 'de' yyyy", { locale: ptBR });
  };

  const formatTime = (date: Date) => {
    return format(date, "HH:mm");
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-50 p-4 transition-opacity duration-300">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg transform transition-all duration-300 scale-95 opacity-0 animate-scale-in">
        <div className="flex justify-between items-center p-4 border-b bg-gray-50 rounded-t-lg">
          <h2 className="text-xl font-bold text-gray-800">Detalhes da Entrevista</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800 transition-colors">
            <X size={24} />
          </button>
        </div>
        
        <div className="p-6 space-y-6">
          <div>
            <h3 className="text-2xl font-bold text-indigo-700">{event.title}</h3>
            <div className="flex items-center text-gray-500 mt-2">
              <Calendar size={16} className="mr-2" />
              <span>{formatDate(event.start)} • {formatTime(event.start)} - {formatTime(event.end)}</span>
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-start">
              <User size={20} className="text-gray-400 mr-4 mt-1 flex-shrink-0" />
              <div>
                <p className="text-sm font-semibold text-gray-500">Candidato</p>
                <p className="text-lg font-medium text-gray-800">{candidate?.nome || candidate?.value || 'Não informado'}</p> {/* Adicionado candidate?.nome */}
              </div>
            </div>
            <div className="flex items-start">
              <Briefcase size={20} className="text-gray-400 mr-4 mt-1 flex-shrink-0" />
              <div>
                <p className="text-sm font-semibold text-gray-500">Vaga</p>
                <p className="text-lg font-medium text-gray-800">{job?.value || 'Não informada'}</p>
              </div>
            </div>
            <div className="flex items-start">
              <Info size={20} className="text-gray-400 mr-4 mt-1 flex-shrink-0" />
              <div>
                <p className="text-sm font-semibold text-gray-500">Detalhes Adicionais</p>
                <p className="text-gray-700 whitespace-pre-wrap">{resource.Detalhes || 'Nenhum detalhe adicional fornecido.'}</p>
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-3"> {/* Contêiner para os botões de ação */}
            {googleEventLink && (
              <a
                href={googleEventLink}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center w-full gap-2 px-4 py-2 text-sm font-semibold rounded-md transition-colors bg-white border border-gray-300 text-gray-700 hover:bg-gray-100"
              >
                <LinkIcon size={16} />
                Ver no Google Calendar
              </a>
            )}

            {/* NOVO: Botão para download do currículo */}
            {candidateCurriculum ? (
              <a
                href={candidateCurriculum.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center w-full gap-2 px-4 py-2 text-sm font-semibold rounded-md transition-colors bg-white border border-gray-300 text-gray-700 hover:bg-gray-100"
              >
                <Download size={16} />
                Baixar Currículo
              </a>
            ) : (
              <button
                disabled
                className="flex items-center justify-center w-full gap-2 px-4 py-2 text-sm font-semibold rounded-md bg-gray-100 text-gray-400 cursor-not-allowed"
                title="Currículo não disponível"
              >
                <Download size={16} />
                Currículo Indisponível
              </button>
            )}
          </div> {/* Fim do contêiner de botões */}
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

export default EventDetailModal;