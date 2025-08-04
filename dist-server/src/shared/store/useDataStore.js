// Local: src/shared/store/useDataStore.ts
import { create } from 'zustand';
export const useDataStore = create((set) => ({
    jobs: [],
    candidates: [],
    isDataLoading: false,
    error: null,
    fetchAllData: async (profile) => {
        set({ isDataLoading: true, error: null });
        try {
            // Chame o endpoint centralizado no seu backend
            const response = await fetch(`/api/data/all/${profile.id}`);
            if (!response.ok) {
                throw new Error('Falha ao carregar dados do servidor.');
            }
            const { jobs, candidates } = await response.json();
            set({ jobs: jobs, candidates: candidates });
        }
        catch (err) {
            console.error("Erro ao buscar dados (useDataStore):", err);
            set({ error: 'Falha ao carregar dados.', jobs: [], candidates: [] });
        }
        finally {
            set({ isDataLoading: false });
        }
    },
    addJob: (job) => {
        set((state) => ({ jobs: [job, ...state.jobs] }));
    },
    updateJobInStore: (updatedJob) => {
        set((state) => ({
            jobs: state.jobs.map(job => job.id === updatedJob.id ? updatedJob : job)
        }));
    },
    deleteJobById: async (jobId) => {
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
        }
        catch (error) {
            console.error("Erro ao deletar vaga (useDataStore):", error);
            throw error; // Re-lança para que o componente chamador possa lidar
        }
    },
    updateCandidateStatusInStore: (candidateId, newStatus) => {
        set((state) => ({
            candidates: state.candidates.map(c => c.id === candidateId ? { ...c, status: { id: 0, value: newStatus } } : c)
        }));
    },
}));
