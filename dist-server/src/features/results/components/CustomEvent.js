// Local: src/features/agenda/components/CustomEvent.tsx
import React from 'react';
import { format } from 'date-fns';
import { User, Briefcase, Clock } from 'lucide-react'; // Adicionamos mais ícones para o modo semana/dia
const CustomEvent = ({ event, view, ...props }) => {
    const candidate = event.resource.Candidato?.[0];
    const startTime = format(event.start, 'HH:mm');
    const endTime = format(event.end, 'HH:mm');
    const isMonthView = view === 'month';
    const backgroundColor = props.style?.backgroundColor || '#6366f1'; // Cor de fundo do evento
    if (isMonthView) {
        // Para a visualização mensal, renderizamos apenas um pequeno ponto colorido.
        // O texto do evento (título, horário, etc.) não aparece diretamente aqui,
        // para manter o calendário limpo. O usuário verá os detalhes na sidebar ou modal.
        return (<div className="rbc-event-content" style={{ backgroundColor }} title={`${event.title} (${startTime} - ${endTime}) com ${candidate?.nome || 'N/A'}`} // Tooltip completo
        >
        {/* Conteúdo vazio, pois o CSS define o ponto visualmente */}
      </div>);
    }
    else {
        // Renderização detalhada para visualizações semanais e diárias (como cards coloridos)
        const textColor = 'white'; // Mantém texto branco para contraste com cores vibrantes
        return (<div className="flex flex-col h-full p-2 rounded-md text-white overflow-hidden" // Aumentamos um pouco o padding
         style={{ backgroundColor }}>
        <strong className="text-sm font-bold truncate" style={{ color: textColor }}>
          {event.title}
        </strong>
        
        {candidate && (<p className="text-xs mt-1 flex items-center opacity-90" style={{ color: textColor }}>
            <User size={14} className="mr-1 flex-shrink-0"/> {/* Ícone para candidato */}
            {candidate.nome || candidate.value}
          </p>)}
        
        {event.resource.Vaga?.[0] && (<p className="text-xs mt-1 flex items-center opacity-90" style={{ color: textColor }}>
                <Briefcase size={14} className="mr-1 flex-shrink-0"/> {/* Ícone para vaga */}
                {event.resource.Vaga[0].value}
            </p>)}

        <p className="text-xs mt-1 flex items-center opacity-90" style={{ color: textColor }}>
            <Clock size={14} className="mr-1 flex-shrink-0"/> {/* Ícone para horário */}
            {startTime} - {endTime}
        </p>
      </div>);
    }
};
export default CustomEvent;
