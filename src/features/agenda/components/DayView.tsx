// Local: src/features/agenda/components/DayView.tsx

import React, { useMemo } from 'react';
import { format, startOfDay, addHours } from 'date-fns';
import { ptBR } from 'date-fns/locale'; // <-- CORRIGIDO: Removido '}}' extra
import { CalendarEvent } from '../types';
import { User, Briefcase, Clock } from 'lucide-react';

interface DayViewProps {
  currentDate: Date; // A data do dia a ser exibido
  events: CalendarEvent[]; // Todos os eventos carregados
  vagaColorMap: Map<number, string>; // Mapa de cores para vagas
  onSelectEvent: (event: CalendarEvent) => void; // Função para selecionar evento (abre modal)
}

const DayView: React.FC<DayViewProps> = ({ currentDate, events, vagaColorMap, onSelectEvent }) => {
  const hoursOfDay = useMemo(() => {
    const hours = [];
    for (let i = 0; i < 24; i++) { // Garante 24 horas (0 a 23)
      hours.push(addHours(startOfDay(currentDate), i));
    }
    return hours;
  }, [currentDate]);

  // Filtra eventos apenas para o dia atual
  const dailyEvents = useMemo(() => {
    return events.filter(event => 
      format(event.start, 'yyyy-MM-dd') === format(currentDate, 'yyyy-MM-dd')
    ).sort((a, b) => a.start.getTime() - b.start.getTime()); // Ordena por hora
  }, [events, currentDate]);

  return (
    // Contêiner principal do DayView. Ele definirá o layout flex e a borda.
    <div className="flex flex-col h-full border rounded-lg overflow-hidden"> 
      {/* Cabeçalho do dia (adaptado do WeekView para um único dia) */}
      <div className="grid grid-cols-2 flex-shrink-0 border-b border-gray-200 bg-gray-50">
        <div className="col-span-1 border-r border-gray-200 calendar-day-header !py-3"></div> {/* Canto superior esquerdo para horas */}
        {/* Cabeçalho do dia atual (ex: QUI 31) */}
        <div className="col-span-1 calendar-day-header">
            {/* Opcional: destaque para o dia de hoje, similar ao WeekView */}
            <span className="block text-sm">{format(currentDate, 'EEE', { locale: ptBR }).toUpperCase()}</span>
            <span className="block text-xl font-bold">{format(currentDate, 'dd')}</span>
        </div>
      </div>

      {/* Área principal com escala de tempo e eventos. ESTE É O CONTÊINER DE SCROLL. */}
      {/* Replicando o comportamento de scroll do WeekView. */}
      <div className="flex-grow overflow-y-auto hide-scrollbar">
        {/* Usamos grid grid-cols-2 para as colunas de horas e eventos. */}
        {/* min-h-full é crucial para forçar a altura e ativar o scroll. */}
        <div className="grid grid-cols-2 min-h-full">
          {/* Coluna das horas - Fica sticky dentro deste contêiner de scroll. */}
          <div className="col-span-1 border-r border-gray-200 sticky left-0 top-0 bg-white z-10"> 
            {hoursOfDay.map((hour, index) => (
              <div key={index} className="h-16 border-b border-dashed border-gray-200 flex items-start justify-end pr-3 pt-1">
                <span className="text-xs text-gray-500">{format(hour, 'HH:mm')}</span>
              </div>
            ))}
          </div>

          {/* Coluna do dia para eventos - Conteúdo que rola junto com o sticky header. */}
          {/* Col-span-1 para a única coluna de eventos. */}
          <div className="col-span-1 relative"> 
            {/* Linhas de tempo para cada hora */}
            {hoursOfDay.map((hour, hourIndex) => (
              <div key={hourIndex} className="h-16 border-b border-dashed border-gray-100 pr-2"></div>
            ))}

            {/* Eventos dentro da coluna do dia */}
            {dailyEvents.map((event) => {
              const eventStartHour = event.start.getHours();
              const eventStartMinutes = event.start.getMinutes();
              const eventEndHour = event.end.getHours();
              const eventEndMinutes = event.end.getMinutes();

              const durationInMinutes = (event.end.getTime() - event.start.getTime()) / (1000 * 60);
              const topOffset = (eventStartHour * 60 + eventStartMinutes) * (64 / 60);
              const height = durationInMinutes * (64 / 60);

              const vagaId = event.resource.Vaga?.[0]?.id;
              const backgroundColor = '#db2777'; // Cor fixa rosa/magenta.

              return (
                <div
                  key={event.resource.id}
                  className="absolute left-1 right-1 p-2 rounded-md text-white overflow-hidden shadow-md cursor-pointer"
                  style={{
                    top: `${topOffset}px`,
                    height: `${height}px`,
                    backgroundColor: backgroundColor,
                    zIndex: 1,
                  }}
                  onClick={() => onSelectEvent(event)}
                >
                  <strong className="text-sm font-bold block truncate">{event.title}</strong>
                  <span className="text-xs block opacity-90"><Clock size={12} className="inline-block mr-1" />{format(event.start, 'HH:mm')} - {format(event.end, 'HH:mm')}</span>
                  {event.resource.Candidato?.[0] && (
                    <span className="text-xs block opacity-80 truncate"><User size={12} className="inline-block mr-1" />{event.resource.Candidato[0].nome || event.resource.Candidato[0].value}</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DayView;