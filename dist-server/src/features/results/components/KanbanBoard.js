// Local: src/features/results/components/KanbanBoard.tsx
import React from 'react';
import KanbanColumn from './KanbanColumn';
const KanbanBoard = ({ candidates, onUpdateStatus, onViewDetails, onScheduleInterview }) => {
    const columns = {
        'Triagem': candidates.filter(c => !c.status || c.status.value === 'Triagem'),
        'Entrevista': candidates.filter(c => c.status?.value === 'Entrevista'),
        'Aprovado': candidates.filter(c => c.status?.value === 'Aprovado'),
        'Reprovado': candidates.filter(c => c.status?.value === 'Reprovado'),
    };
    return (<div className="flex gap-6 pb-2 overflow-x-auto h-full flex-grow hide-scrollbar">
        <KanbanColumn columnId="Triagem" title="Triagem" candidates={columns['Triagem']} onViewDetails={onViewDetails} onScheduleInterview={onScheduleInterview} onUpdateStatus={onUpdateStatus}/>
        <KanbanColumn columnId="Entrevista" title="Entrevista" candidates={columns['Entrevista']} onViewDetails={onViewDetails} onScheduleInterview={onScheduleInterview} onUpdateStatus={onUpdateStatus}/>
        <KanbanColumn columnId="Aprovado" title="Aprovado" candidates={columns['Aprovado']} onViewDetails={onViewDetails} onScheduleInterview={onScheduleInterview} onUpdateStatus={onUpdateStatus}/>
        <KanbanColumn columnId="Reprovado" title="Reprovado" candidates={columns['Reprovado']} onViewDetails={onViewDetails} onScheduleInterview={onScheduleInterview} onUpdateStatus={onUpdateStatus}/>
    </div>);
};
export default KanbanBoard;
