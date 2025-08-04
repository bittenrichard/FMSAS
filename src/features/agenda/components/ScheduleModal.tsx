// Local: src/features/agenda/components/ScheduleModal.tsx

import React, { useState } from 'react';
import { X, Calendar } from 'lucide-react';
import { Candidate } from '../../results/types';
import { addHours } from 'date-fns';

interface ScheduleModalProps {
  isOpen: boolean;
  onClose: () => void;
  candidate: Candidate | null;
  onSchedule: (details: { start: Date; end: Date; title: string; details: string; saveToGoogle: boolean }) => Promise<void>;
}

const ScheduleModal: React.FC<ScheduleModalProps> = ({ isOpen, onClose, candidate, onSchedule }) => {
  const [date, setDate] = useState('');
  const [startTime, setStartTime] = useState('');
  const [details, setDetails] = useState('');
  const [saveToGoogle, setSaveToGoogle] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen || !candidate) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!date || !startTime) {
      alert('Por favor, preencha a data e o horário de início.');
      return;
    }

    setIsSubmitting(true);
    const startDateTime = new Date(`${date}T${startTime}`);
    const endDateTime = addHours(startDateTime, 1);
    
    await onSchedule({
      start: startDateTime,
      end: endDateTime,
      title: `Entrevista - ${candidate.nome}`,
      details: details,
      saveToGoogle: saveToGoogle
    });
    
    setIsSubmitting(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-bold text-gray-800">Agendar Entrevista</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800"><X size={24} /></button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="p-6 space-y-4">
            <p className="text-gray-600">Agendando entrevista para: <span className="font-bold">{candidate.nome}</span></p>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="date" className="block text-sm font-medium text-gray-700">Data da Entrevista</label>
                <input type="date" id="date" value={date} onChange={e => setDate(e.target.value)} required className="mt-1 block w-full border-gray-300 rounded-md shadow-sm"/>
              </div>
              <div>
                <label htmlFor="start-time" className="block text-sm font-medium text-gray-700">Início</label>
                <input type="time" id="start-time" value={startTime} onChange={e => setStartTime(e.target.value)} required className="mt-1 block w-full border-gray-300 rounded-md shadow-sm"/>
              </div>
            </div>
            <div>
              <label htmlFor="details" className="block text-sm font-medium text-gray-700">Detalhes (Opcional)</label>
              <textarea id="details" value={details} onChange={e => setDetails(e.target.value)} rows={3} placeholder="Ex: Link da chamada de vídeo, endereço, etc." className="mt-1 block w-full border-gray-300 rounded-md shadow-sm"></textarea>
            </div>
             <div className="pt-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={saveToGoogle}
                  onChange={(e) => setSaveToGoogle(e.target.checked)}
                  className="h-4 w-4 text-indigo-600 border-gray-300 rounded"
                />
                <span className="ml-3 text-sm text-gray-700 flex items-center">
                  <Calendar size={16} className="mr-2 text-gray-500"/>
                  Salvar no Google Calendar
                </span>
              </label>
               <p className="text-xs text-gray-500 ml-7 mt-1">Requer autenticação com sua conta Google.</p>
            </div>
          </div>
          <div className="bg-gray-50 px-6 py-3 flex justify-end">
            <button type="button" onClick={onClose} disabled={isSubmitting} className="mr-3 bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50">Cancelar</button>
            <button type="submit" disabled={isSubmitting} className="bg-indigo-600 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
              {isSubmitting ? 'Agendando...' : 'Confirmar Agendamento'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ScheduleModal;