// Local: src/features/screening/types/index.ts

// Representa uma Vaga como vem da API do Baserow
export interface JobPosting {
  id: number;
  order: string;
  titulo: string;
  descricao: string;
  endereco: string; // <-- ADICIONADO
  requisitos_obrigatorios: string;
  requisitos_desejaveis: string;
  criado_em: string;
  usuario: { id: number; value: string }[];
  // Campos que calcularemos depois
  candidateCount?: number;
  averageScore?: number;
}

// Representa os dados do formulário de criação de vaga
export interface JobFormData {
  jobTitle: string;
  jobDescription: string;
  endereco: string; // <-- ADICIONADO
  requiredSkills: string;
  desiredSkills: string;
}