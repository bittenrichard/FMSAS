// Local: src/shared/types/index.ts

// Chave da página para navegação - ADICIONAMOS 'edit-screening'
export type PageKey = 'login' | 'signup' | 'dashboard' | 'new-screening' | 'edit-screening' | 'results' | 'settings' | 'database' | 'agenda';

// Representa um Candidato como vem da API do Baserow
export interface Candidate {
  id: number;
  order: string;
  nome: string;
  email?: string;
  telefone: string | null;
  score: number | null;
  resumo_ia: string | null;
  data_triagem: string;
  vaga: { id: number; value: string }[] | null;
  usuario: { id: number; value: string }[] | null;
  curriculo?: { url: string; name: string }[] | null;
  
  cidade?: string;
  bairro?: string;
  idade?: number;
  sexo?: string;
  escolaridade?: string;
  status?: { id: number; value: 'Triagem' | 'Entrevista' | 'Aprovado' | 'Reprovado' } | null;
}