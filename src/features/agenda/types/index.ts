import { Candidate } from "../../results/types";
import { JobPosting } from "../../screening/types";

// Representa um agendamento como vem do Baserow
export interface ScheduleEvent {
  id: number;
  Título: string;
  Início: string; // Formato ISO (ex: "2025-07-28T14:00:00Z")
  Fim: string;
  Detalhes?: string;
  Candidato: Candidate[]; // Link to table retorna um array
  Vaga: JobPosting[];
}

// Formato que o componente de calendário espera
export interface CalendarEvent {
  title: string;
  start: Date;
  end: Date;
  resource: ScheduleEvent; // Guarda o evento original do Baserow
}