import { create } from 'zustand';
import { DataState, UserProfile, ScreeningData, CandidateData } from '../types';

// A URL base da API é lida da variável de ambiente injetada pelo Vite
const API_URL = import.meta.env.VITE_API_BASE_URL;

export const useDataStore = create<DataState>((set) => ({
    screeningData: [],
    candidateData: [],
    isDataLoading: true,
    error: null,
    
    fetchAllData: async (profile: UserProfile) => {
        set({ isDataLoading: true, error: null });
        try {
            // Fetch screening data
            const screeningResponse = await fetch(`${API_URL}/api/data/all/${profile.id}`);
            if (!screeningResponse.ok) throw new Error('Falha ao buscar dados de triagem');
            const screeningData: ScreeningData[] = await screeningResponse.json();

            // Fetch candidate data
            const candidateResponse = await fetch(`${API_URL}/api/data/candidate-base/${profile.id}`);
            if (!candidateResponse.ok) throw new Error('Falha ao buscar dados de candidatos');
            const candidateData: CandidateData[] = await candidateResponse.json();

            set({
                screeningData,
                candidateData,
                isDataLoading: false,
            });
        } catch (error: any) {
            set({ error: error.message, isDataLoading: false });
        }
    },
}));