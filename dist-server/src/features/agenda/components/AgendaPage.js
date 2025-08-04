// Local: src/features/agenda/components/AgendaPage.tsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Loader2, ChevronRight, ChevronLeft } from 'lucide-react';
import { format, addMonths, subMonths, addWeeks, subWeeks, addDays, subDays, startOfWeek, endOfWeek, isSameDay } from 'date-fns';
import { ptBR } from 'date-fns/locale';
import EventDetailModal from './EventDetailModal';
import DailyEventsSidebar from './DailyEventsSidebar';
import { useAuth } from '../../../features/auth/hooks/useAuth';
// Novos componentes para as visualizações do calendário
import MonthView from './MonthView';
import WeekView from './WeekView';
import DayView from './DayView';
// Geração de cores otimizada para ser mais performática e previsível
const generateColorForId = (id) => {
    const colors = [
        '#4f46e5', // indigo-600
        '#059669', // green-700
        '#db2777', // pink-600
        '#d97706', // amber-700
        '#0891b2', // cyan-700
        '#6d28d9', // violet-700
        '#be185d', // rose-700
        '#ef4444', // red-500
        '#f97316', // orange-500
        '#eab308', // yellow-500
        '#84cc16', // lime-500
        '#22c55e', // emerald-500
        '#14b8a6', // teal-500
        '#06b6d4', // sky-500
        '#3b82f6', // blue-500
        '#a855f7', // purple-500
        '#d946ef', // fuchsia-500
        '#ec4899', // rose-500 (light)
        '#f43f5e' // pink-500 (light)
    ];
    return colors[id % colors.length];
};
const AgendaPage = () => {
    const { profile } = useAuth();
    const [events, setEvents] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [currentDate, setCurrentDate] = useState(new Date()); // Data que o calendário está mostrando
    const [selectedDayForSidebar, setSelectedDayForSidebar] = useState(new Date()); // Dia selecionado para a sidebar
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [currentView, setCurrentView] = useState('month');
    // Mapa de cores para as vagas/eventos
    const vagaColorMap = useMemo(() => {
        const map = new Map();
        events.forEach(event => {
            const vagaId = event.resource.Vaga?.[0]?.id;
            if (vagaId && !map.has(vagaId)) {
                const color = generateColorForId(vagaId);
                map.set(vagaId, color);
                // NOVO: Log para depuração dos IDs de vaga e cores
                console.log(`Vaga ID: ${vagaId}, Cor Atribuída: ${color}`);
            }
        });
        return map;
    }, [events]);
    // Eventos filtrados para a sidebar do dia selecionado
    const dailyEvents = useMemo(() => {
        return events.filter(event => isSameDay(event.start, selectedDayForSidebar)).sort((a, b) => a.start.getTime() - b.start.getTime()); // Ordena por hora
    }, [events, selectedDayForSidebar]);
    // Função para buscar agendamentos do backend
    const fetchSchedules = useCallback(async () => {
        if (!profile?.id) {
            setIsLoading(false);
            setError("Usuário não logado. Não foi possível carregar agendamentos.");
            return;
        }
        setIsLoading(true);
        setError(null);
        try {
            const response = await fetch(`/api/schedules/${profile.id}`);
            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.message || 'Erro ao buscar agendamentos do backend.');
            }
            const { results } = await response.json();
            if (results) {
                // NOVO: Log para depuração dos resultados brutos do backend
                console.log("Resultados brutos do Baserow para Agendamentos:", results);
                const formattedEvents = results.map((event) => ({
                    title: event.Título,
                    start: new Date(event.Início),
                    end: new Date(event.Fim),
                    resource: event,
                }));
                setEvents(formattedEvents);
                // NOVO: Log para depuração dos eventos formatados
                console.log("Eventos formatados:", formattedEvents);
            }
        }
        catch (err) {
            console.error("Erro ao buscar agendamentos:", err);
            setError(err.message || "Não foi possível carregar agendamentos. Tente novamente.");
        }
        finally {
            setIsLoading(false);
        }
    }, [profile?.id]);
    useEffect(() => {
        fetchSchedules();
    }, [fetchSchedules]);
    const handleSelectEvent = useCallback((event) => {
        setSelectedEvent(event);
    }, []);
    const handleDayClick = useCallback((date) => {
        setSelectedDayForSidebar(date);
        // Opcional: Mudar para visualização de Dia ao clicar em um dia específico
        //setCurrentView('day'); 
        setIsSidebarOpen(true);
    }, []);
    const handleNavigate = useCallback((direction) => {
        let newDate = currentDate;
        if (direction === 'prev') {
            if (currentView === 'month')
                newDate = subMonths(currentDate, 1);
            else if (currentView === 'week')
                newDate = subWeeks(currentDate, 1);
            else if (currentView === 'day')
                newDate = subDays(currentDate, 1);
        }
        else if (direction === 'next') {
            if (currentView === 'month')
                newDate = addMonths(currentDate, 1);
            else if (currentView === 'week')
                newDate = addWeeks(currentDate, 1);
            else if (currentView === 'day')
                newDate = addDays(currentDate, 1);
        }
        else if (direction === 'today') {
            newDate = new Date(); // Vai para a data atual
        }
        setCurrentDate(newDate);
        setSelectedDayForSidebar(newDate); // Mantém a sidebar no dia da navegação
    }, [currentDate, currentView]);
    const handleViewChange = useCallback((view) => {
        setCurrentView(view);
    }, []);
    // Determinar o título do período exibido (Ex: Julho 2025)
    const getPeriodLabel = useMemo(() => {
        if (currentView === 'month') {
            return format(currentDate, 'MMMM yyyy', { locale: ptBR });
        }
        else if (currentView === 'week') {
            const startOfWeekDate = startOfWeek(currentDate, { locale: ptBR });
            const endOfWeekDate = endOfWeek(currentDate, { locale: ptBR });
            const startDay = format(startOfWeekDate, 'd', { locale: ptBR });
            const endDay = format(endOfWeekDate, 'd', { locale: ptBR });
            const startMonth = format(startOfWeekDate, 'MMM', { locale: ptBR });
            const endMonth = format(endOfWeekDate, 'MMM', { locale: ptBR });
            if (startMonth === endMonth) {
                return `${startDay} - ${endDay} ${format(startOfWeekDate, 'MMMM yyyy', { locale: ptBR })}`;
            }
            else {
                return `${startDay} ${startMonth} - ${endDay} ${endMonth} ${format(endOfWeekDate, 'yyyy', { locale: ptBR })}`;
            }
        }
        else if (currentView === 'day') {
            return format(currentDate, "EEEE, dd 'de' MMMM", { locale: ptBR });
        }
        return ''; // Fallback
    }, [currentDate, currentView]);
    if (isLoading) {
        return (<div className="flex justify-center items-center h-full">
        <Loader2 className="h-12 w-12 text-indigo-600 animate-spin"/>
      </div>);
    }
    return (<div className="fade-in flex h-full gap-6 p-6">
      {/* Container principal do calendário */}
      <div className="flex flex-col flex-grow calendar-container">
        {error && (<div className="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                {error}
            </div>)}
        
        {/* Cabeçalho do Calendário (Toolbar customizada) */}
        <div className="flex items-center justify-between p-4 bg-white border-b border-gray-200 rounded-t-lg">
            {/* Navegação */}
            <div className="flex items-center gap-2">
                <button onClick={() => handleNavigate('prev')} className="p-2 text-gray-500 hover:text-indigo-600 rounded-full hover:bg-gray-100 transition-colors" title="Período Anterior">
                <ChevronLeft size={20}/>
                </button>
                <h2 className="text-xl font-bold text-gray-800 capitalize flex-shrink-0 mx-2">
                {getPeriodLabel}
                </h2>
                <button onClick={() => handleNavigate('next')} className="p-2 text-gray-500 hover:text-indigo-600 rounded-full hover:bg-gray-100 transition-colors" title="Próximo Período">
                <ChevronRight size={20}/>
                </button>
            </div>

            {/* Seleção de Visualização e Hoje */}
            <div className="flex items-center gap-4 ml-auto">
                <div className="inline-flex items-center bg-gray-100 p-1 rounded-lg"> 
                    <button onClick={() => handleViewChange('month')} className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors duration-200 
                        ${currentView === 'month'
            ? 'bg-blue-600 text-white shadow-sm'
            : 'text-gray-600 hover:bg-gray-200'}`}>
                        Mês
                    </button>
                    <button onClick={() => handleViewChange('week')} className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors duration-200 
                        ${currentView === 'week'
            ? 'bg-blue-600 text-white shadow-sm'
            : 'text-gray-600 hover:bg-gray-200'}`}>
                        Semana
                    </button>
                    <button onClick={() => handleViewChange('day')} className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors duration-200 
                        ${currentView === 'day'
            ? 'bg-blue-600 text-white shadow-sm'
            : 'text-gray-600 hover:bg-gray-200'}`}>
                        Dia
                    </button>
                </div>
                <button type="button" onClick={() => handleNavigate('today')} className="px-4 py-2 text-sm font-semibold text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 transition-colors shadow-sm" title="Ir para Hoje">
                    Hoje
                </button>
            </div>
        </div>
        
        {/* Renderiza a visualização do calendário baseada no estado currentView */}
        <div className="flex-grow relative h-full p-4">
            {currentView === 'month' && (<MonthView currentDate={currentDate} events={events} onDayClick={handleDayClick} selectedDayForSidebar={selectedDayForSidebar} vagaColorMap={vagaColorMap} onSelectEvent={handleSelectEvent}/>)}
            {currentView === 'week' && (<WeekView currentDate={currentDate} events={events} onDayClick={handleDayClick} selectedDayForSidebar={selectedDayForSidebar} vagaColorMap={vagaColorMap} onSelectEvent={handleSelectEvent}/>)}
            {currentView === 'day' && (<DayView currentDate={currentDate} events={events} vagaColorMap={vagaColorMap} onSelectEvent={handleSelectEvent}/>)}
        </div>
      </div>
      
      {/* Sidebar de eventos diários (mantida como está) */}
      <div className={`
        flex-shrink-0 transition-all duration-300 ease-in-out
        ${isSidebarOpen ? 'w-80 ml-6' : 'w-12 ml-6'}
        bg-white rounded-lg shadow-sm border border-gray-100 flex flex-col relative
      `}>
        {/* Botão de esconder/mostrar sidebar */}
        <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className={`
            absolute p-1 rounded-full shadow-sm z-10 transition-transform duration-300
            flex items-center justify-center border border-gray-200
            ${isSidebarOpen
            ? '-left-3 top-4 bg-white text-gray-500 hover:bg-gray-100'
            : 'left-1/2 -translate-x-1/2 top-4 bg-gray-100 text-gray-600 hover:bg-gray-200'}
          `} title={isSidebarOpen ? "Esconder eventos diários" : "Mostrar eventos diários"}>
          {isSidebarOpen ? <ChevronRight size={16}/> : <ChevronLeft size={16}/>}
        </button>
        {isSidebarOpen && (<DailyEventsSidebar selectedDate={selectedDayForSidebar} events={dailyEvents} onViewDetails={handleSelectEvent} vagaColorMap={vagaColorMap}/>)}
      </div>

      {selectedEvent && (<EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)}/>)}
    </div>);
};
export default AgendaPage;
