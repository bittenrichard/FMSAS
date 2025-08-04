// Local: src/features/results/components/KanbanColumn.tsx
import React from 'react';
import CandidateCard from './CandidateCard';
const KanbanColumn = ({ columnId, title, candidates, onViewDetails, onScheduleInterview, onUpdateStatus }) => {
    return (<div className="bg-gray-100 rounded-lg p-4 w-full md:w-80 lg:w-96 flex-shrink-0 flex flex-col min-h-full">
      <h3 className="font-bold text-gray-800 mb-4 px-2 flex-shrink-0">{title} ({candidates.length})</h3>
      
      <div className={`p-2 rounded-md transition-colors duration-200 border-2 border-dashed border-transparent`}>
        {candidates.map((candidate, index) => (<CandidateCard key={candidate.id} candidate={candidate} index={index} onViewDetails={onViewDetails} onScheduleInterview={onScheduleInterview} onUpdateStatus={onUpdateStatus}/>))}
      </div>
    </div>);
};
export default KanbanColumn;
