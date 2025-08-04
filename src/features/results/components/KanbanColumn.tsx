// Local: src/features/results/components/KanbanColumn.tsx

import React from 'react';
import { useDrop } from 'react-dnd';
import { Candidate } from '../../../shared/types';
import CandidateCard from './CandidateCard';

interface KanbanColumnProps {
  columnId: 'Triagem' | 'Entrevista' | 'Aprovado' | 'Reprovado';
  title: string;
  candidates: Candidate[];
  onViewDetails: (candidate: Candidate) => void;
  onScheduleInterview: (candidate: Candidate) => void;
  onUpdateStatus: (candidateId: number, newStatus: 'Triagem' | 'Entrevista' | 'Aprovado' | 'Reprovado') => void;
}

const KanbanColumn: React.FC<KanbanColumnProps> = ({ columnId, title, candidates, onViewDetails, onScheduleInterview, onUpdateStatus }) => {
    
  // CORREÇÃO: Hook useDrop para que a coluna seja uma zona de destino
  const [{ isOver }, drop] = useDrop(() => ({
    accept: 'candidateCard', // Aceita apenas itens do tipo 'candidateCard'
    drop: (item: { id: number }) => onUpdateStatus(item.id, columnId),
    collect: (monitor) => ({
      isOver: !!monitor.isOver(),
    }),
  }));
    
  return (
    <div className="bg-gray-100 rounded-lg p-4 w-full md:w-80 lg:w-96 flex-shrink-0 flex flex-col min-h-full">
      <h3 className="font-bold text-gray-800 mb-4 px-2 flex-shrink-0">{title} ({candidates.length})</h3>
      
      {/* CORREÇÃO: Atribuir a referência 'drop' ao div */}
      <div 
        ref={drop}
        className={`p-2 rounded-md transition-colors duration-200 border-2 border-dashed
          ${isOver ? 'border-indigo-400 bg-indigo-50' : 'border-transparent'}
          h-full`}
      >
        {candidates.map((candidate) => (
          <CandidateCard
            key={candidate.id}
            candidate={candidate}
            onViewDetails={onViewDetails}
            onScheduleInterview={onScheduleInterview}
            onUpdateStatus={onUpdateStatus}
          />
        ))}
      </div>
    </div>
  );
};

export default KanbanColumn;