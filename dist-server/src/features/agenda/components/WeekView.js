// Local: src/features/agenda/components/WeekView.tsx
import React, { useMemo } from 'react';
import { format, startOfWeek, endOfWeek, eachDayOfInterval, isSameDay, addHours, startOfDay, isToday } from 'date-fns';
import { ptBR } from 'date-fns/locale'; // <-- CORRIGIDO: Removido '}}' extra
import { User, Clock } from 'lucide-react';
const WeekView = ({ currentDate, events, onDayClick, selectedDayForSidebar, vagaColorMap, onSelectEvent }) => {
    const daysOfWeek = useMemo(() => {
        const start = startOfWeek(currentDate, { locale: ptBR });
        const end = endOfWeek(currentDate, { locale: ptBR });
        return eachDayOfInterval({ start, end });
    }, [currentDate]);
    const hoursOfDay = useMemo(() => {
        const hours = [];
        for (let i = 0; i < 24; i++) {
            hours.push(addHours(startOfDay(currentDate), i));
        }
        return hours;
    }, [currentDate]);
    const eventsByDay = useMemo(() => {
        const map = new Map();
        events.forEach(event => {
            const dayKey = format(event.start, 'yyyy-MM-dd');
            if (!map.has(dayKey)) {
                map.set(dayKey, []);
            }
            map.get(dayKey)?.push(event);
        });
        return map;
    }, [events]);
    return (<div className="flex flex-col h-full overflow-hidden">
      {/* Cabeçalho dos dias da semana (ex: DOM 29, SEG 30) */}
      <div className="grid grid-cols-8 flex-shrink-0 border-b border-gray-200 bg-gray-50">
        <div className="col-span-1 border-r border-gray-200 calendar-day-header !py-3"></div> {/* Canto superior esquerdo para horas */}
        {daysOfWeek.map((day, index) => (<div key={index} className={`col-span-1 calendar-day-header ${isSameDay(day, selectedDayForSidebar) ? 'is-selected' : ''} ${isToday(day) ? 'is-today' : ''}`} onClick={() => onDayClick(day)} // Permite selecionar o dia clicando no cabeçalho
        >
            <span className="block text-sm">{format(day, 'EEE', { locale: ptBR }).toUpperCase()}</span>
            <span className="block text-xl font-bold">{format(day, 'dd')}</span>
          </div>))}
      </div>

      {/* Área principal com escala de tempo e eventos */}
      <div className="flex-grow overflow-y-auto hide-scrollbar">
        <div className="grid grid-cols-8 min-h-full">
          {/* Coluna das horas */}
          <div className="col-span-1 border-r border-gray-200 sticky left-0 bg-white z-10">
            {hoursOfDay.map((hour, index) => (<div key={index} className="h-16 border-b border-dashed border-gray-200 flex items-start justify-end pr-3 pt-1">
                <span className="text-xs text-gray-500">{format(hour, 'HH:mm')}</span>
              </div>))}
          </div>

          {/* Colunas dos dias para eventos */}
          {daysOfWeek.map((day, dayIndex) => {
            const dayKey = format(day, 'yyyy-MM-dd');
            const dayEvents = eventsByDay.get(dayKey) || [];
            return (<div key={dayIndex} className={`col-span-1 relative border-r border-gray-100 `}>
                {/* Linhas de tempo para cada hora */}
                {hoursOfDay.map((hour, hourIndex) => (<div key={hourIndex} className="h-16 border-b border-dashed border-gray-100"></div>))}

                {/* Eventos dentro da coluna do dia */}
                {dayEvents.map((event) => {
                    const eventStartHour = event.start.getHours();
                    const eventStartMinutes = event.start.getMinutes();
                    const eventEndHour = event.end.getHours();
                    const eventEndMinutes = event.end.getMinutes();
                    const durationInMinutes = (event.end.getTime() - event.start.getTime()) / (1000 * 60);
                    const topOffset = (eventStartHour * 60 + eventStartMinutes) * (64 / 60); // 64px = height of each hour slot
                    const height = durationInMinutes * (64 / 60);
                    const vagaId = event.resource.Vaga?.[0]?.id;
                    const backgroundColor = '#db2777'; // Cor fixa rosa/magenta.
                    return (<div key={event.resource.id} className="absolute left-1 right-1 p-1 rounded-md text-white overflow-hidden shadow-md cursor-pointer" style={{
                            top: `${topOffset}px`,
                            height: `${height}px`,
                            backgroundColor: backgroundColor,
                            zIndex: 1,
                        }} onClick={() => onSelectEvent(event)}>
                      <strong className="text-xs font-bold block truncate">{event.title}</strong>
                      <span className="text-xs block opacity-90"><Clock size={12} className="inline-block mr-1"/>{format(event.start, 'HH:mm')} - {format(event.end, 'HH:mm')}</span>
                      {event.resource.Candidato?.[0] && (<span className="text-xs block opacity-80 truncate"><User size={12} className="inline-block mr-1"/>{event.resource.Candidato[0].nome || event.resource.Candidato[0].value}</span>)}
                    </div>);
                })}
              </div>);
        })}
        </div>
      </div>
    </div>);
};
export default WeekView;
