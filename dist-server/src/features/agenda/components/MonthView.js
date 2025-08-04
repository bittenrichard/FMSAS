// Local: src/features/agenda/components/MonthView.tsx
import React, { useMemo } from 'react';
import { format, startOfMonth, endOfMonth, startOfWeek, endOfWeek, eachDayOfInterval, isSameMonth, isToday, isSameDay } from 'date-fns';
import { ptBR } from 'date-fns/locale'; // <-- CORRIGIDO: Removido '}}' extra
const MonthView = ({ currentDate, events, onDayClick, selectedDayForSidebar, vagaColorMap, onSelectEvent }) => {
    const daysOfWeek = ['domingo', 'segunda', 'terça', 'quarta', 'quinta', 'sexta', 'sábado'];
    const calendarDays = useMemo(() => {
        const startOfCurrentMonth = startOfMonth(currentDate);
        const endOfCurrentMonth = endOfMonth(currentDate);
        const firstDayOfCalendar = startOfWeek(startOfCurrentMonth, { locale: ptBR });
        const lastDayOfCalendar = endOfWeek(endOfCurrentMonth, { locale: ptBR });
        return eachDayOfInterval({ start: firstDayOfCalendar, end: lastDayOfCalendar });
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
    const MAX_VISIBLE_DOTS = 3;
    return (<div className="grid grid-cols-7 gap-1 h-full">
      {/* Cabeçalho dos dias da semana */}
      {daysOfWeek.map((day, index) => (<div key={index} className="calendar-day-header">
          {day.substring(0, 3)}
        </div>))}

      {/* Células dos dias do mês */}
      {calendarDays.map((day, index) => {
            const dayKey = format(day, 'yyyy-MM-dd');
            const dayEvents = eventsByDay.get(dayKey) || [];
            const isCurrentMonthDay = isSameMonth(day, currentDate);
            const isTodayDate = isToday(day);
            const isSelectedDay = isSameDay(day, selectedDayForSidebar);
            const dayCellClasses = [
                'calendar-day-cell',
                isTodayDate ? 'is-today' : '',
                isSelectedDay ? 'is-selected' : '',
                !isCurrentMonthDay ? 'opacity-50 pointer-events-none' : '',
            ].filter(Boolean).join(' ');
            return (<div key={index} className={dayCellClasses} onClick={() => onDayClick(day)}>
            {/* Número do dia */}
            <span className="calendar-day-number">
              {format(day, 'dd')}
            </span>

            {/* Container para os pontos de evento */}
            {isCurrentMonthDay && dayEvents.length > 0 && (<div className="calendar-event-dot-container">
                {dayEvents.slice(0, MAX_VISIBLE_DOTS).map((event, eventIdx) => (<div key={event.resource.id || eventIdx} className="calendar-event-dot" 
                    // Cor fixa rosa/magenta.
                    style={{ backgroundColor: '#db2777' }} title={`${event.title} (${format(event.start, 'HH:mm')} - ${format(event.end, 'HH:mm')})`} onClick={(e) => {
                            e.stopPropagation();
                            onSelectEvent(event);
                        }}/>))}
                {dayEvents.length > MAX_VISIBLE_DOTS && (<span className="calendar-more-events" onClick={(e) => {
                            e.stopPropagation();
                            onDayClick(day);
                        }}>
                    +{dayEvents.length - MAX_VISIBLE_DOTS} more
                  </span>)}
              </div>)}
          </div>);
        })}
    </div>);
};
export default MonthView;
