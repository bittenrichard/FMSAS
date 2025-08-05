// Local: src/shared/store/useDataStore.ts

import { create } from 'zustand';
import { JobPosting } from '../../features/screening/types';
import { Candidate } from '../../shared/types';
import { UserProfile } from '../../features/auth/types';
// Remova: import { baserow } from '../services/baserowClient'; // REMOVA esta linha
// Remova: const VAGAS_TABLE_ID = '709'; // REMOVA esta linha
// Remova: const CANDIDATOS_TABLE_ID = '710'; // REMOVA esta linha
// Remova: const WHATSAPP_CANDIDATOS_TABLE_ID = '712'; // REMOVA esta linha

interface DataState {
  jobs: JobPosting[];
  candidates: Candidate[];
  isDataLoading: boolean;
  error: string | null;
  fetchAllData: (profile: UserProfile) => Promise<void>;
  addJob: (job: JobPosting) => void;
  updateJobInStore: (updatedJob: JobPosting) => void;
  deleteJobById: (jobId: number) => Promise<void>;
  updateCandidateStatusInStore: (candidateId: number, newStatus: 'Triagem' | 'Entrevista' | 'Aprovado' | 'Reprovado') => void;
}

export const useDataStore = create<DataState>((set) => ({
  jobs: [],
  candidates: [],
  isDataLoading: false,
  error: null,

  fetchAllData: async (profile: UserProfile) => {
    set({ isDataLoading: true, error: null });
    try {
      // Chame o endpoint centralizado no seu backend
      const response = await fetch(`/api/data/all/${profile.id}`);
      if (!response.ok) {
        throw new Error('Falha ao carregar dados do servidor.');
      }
      const { jobs, candidates } = await response.json();
      
      set({ jobs: jobs, candidates: candidates });
    } catch (err: any) {
      console.error("Erro ao buscar dados (useDataStore):", err);
      set({ error: 'Falha ao carregar dados.', jobs: [], candidates: [] });
    } finally {
      set({ isDataLoading: false });
    }
  },

  addJob: (job: JobPosting) => {
    set((state) => ({ jobs: [job, ...state.jobs] }));
  },

  updateJobInStore: (updatedJob: JobPosting) => {
    set((state) => ({
      jobs: state.jobs.map(job => job.id === updatedJob.id ? updatedJob : job)
    }));
  },

  deleteJobById: async (jobId: number) => {
    try {
      // Chame o backend para deletar a vaga
      const response = await fetch(`/api/jobs/${jobId}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        const errorData = await response.json(); // Tenta ler o erro do corpo
        throw new Error(errorData.error || "Não foi possível excluir a vaga.");
      }
      set((state) => ({
        jobs: state.jobs.filter(job => job.id !== jobId)
      }));
    } catch (error) {
      console.error("Erro ao deletar vaga (useDataStore):", error);
      throw error; // Re-lança para que o componente chamador possa lidar
    }
  },

  updateCandidateStatusInStore: (candidateId: number, newStatus: 'Triagem' | 'Entrevista' | 'Aprovado' | 'Reprovado') => {
    set((state) => ({
      candidates: state.candidates.map(c => 
        // Verifica se é o candidato correto e atualiza o status
        c.id === candidateId ? { ...c, status: { id: 0, value: newStatus } } : c
      )
    }));
  },
}));