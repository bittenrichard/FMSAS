// Local: src/features/agenda/components/CustomToolbar.tsx
import React from 'react';
import { Navigate, Views } from 'react-big-calendar';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { format, getDay } from 'date-fns';
import { ptBR } from 'date-fns/locale';
const CustomToolbar = ({ label, view, views, onNavigate, onView, date }) => {
    const viewNames = {
        month: 'Mês',
        week: 'Semana',
        day: 'Dia',
    };
    const getRangeLabel = () => {
        if (view === Views.WEEK) {
            const startOfWeekDate = new Date(date.getFullYear(), date.getMonth(), date.getDate() - getDay(date));
            const endOfWeekDate = new Date(date.getFullYear(), date.getMonth(), date.getDate() - getDay(date) + 6);
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
        if (view === Views.DAY) {
            return format(date, "EEEE, dd 'de' MMMM", { locale: ptBR });
        }
        return label;
    };
    return (<div className="flex items-center justify-between p-4 bg-white border-b border-gray-200 rounded-t-lg"> 
      
      <div className="flex items-center gap-2">
        <button onClick={() => onNavigate(Navigate.PREVIOUS)} className="p-2 text-gray-500 hover:text-indigo-600 rounded-full hover:bg-gray-100 transition-colors" title="Mês/Semana/Dia Anterior">
          <ChevronLeft size={20}/>
        </button>
        <h2 className="text-xl font-bold text-gray-800 capitalize flex-shrink-0 mx-2">
          {getRangeLabel()}
        </h2>
        <button onClick={() => onNavigate(Navigate.NEXT)} className="p-2 text-gray-500 hover:text-indigo-600 rounded-full hover:bg-gray-100 transition-colors" title="Próximo Mês/Semana/Dia">
          <ChevronRight size={20}/>
        </button>
      </div>

      <div className="flex items-center gap-4 ml-auto">
        <div className="inline-flex items-center bg-gray-100 p-1 rounded-lg"> 
            {views.filter(v => viewNames[v]).map(viewName => (<button key={viewName} onClick={() => onView(viewName)} className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors duration-200 
                ${view === viewName
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-gray-600 hover:bg-gray-200'}`}>
                {viewNames[viewName]}
            </button>))}
        </div>
        <button type="button" onClick={() => onNavigate(Navigate.TODAY)} className="px-4 py-2 text-sm font-semibold text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 transition-colors shadow-sm" title="Ir para Hoje">
            Hoje
        </button>
      </div>
    </div>);
};
export default CustomToolbar;
