// Local: src/features/screening/hooks/useJobForm.ts

import { useState, useCallback } from 'react';
import { JobFormData, JobPosting } from '../types';
import { useAuth } from '../../auth/hooks/useAuth';

// Pega a URL base da API das variáveis de ambiente do Vite
const API_BASE_URL = 'https://api.recrutamentoia.com.br';

export const useJobForm = () => {
  const { profile } = useAuth();
  const [formData, setFormData] = useState<JobFormData>({
    jobTitle: '',
    jobDescription: '',
    endereco: '',
    requiredSkills: '',
    desiredSkills: ''
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateField = (field: keyof JobFormData, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };
  
  const setInitialData = useCallback((data: JobFormData) => {
    setFormData(data);
  }, []);

  const submitJob = async (): Promise<JobPosting | null> => {
    if (!profile) {
      setError("Você precisa estar logado para criar uma vaga.");
      return null;
    }

    setIsSubmitting(true);
    setError(null);
    
    try {
      const newJobData = {
        "titulo": formData.jobTitle,
        "descricao": formData.jobDescription,
        "endereco": formData.endereco,
        "requisitos_obrigatorios": formData.requiredSkills,
        "requisitos_desejaveis": formData.desiredSkills,
        "usuario": [profile.id]
      };

      const response = await fetch(`${API_BASE_URL}/api/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newJobData),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Não foi possível criar a vaga. Tente novamente.");
      }
      
      setIsSubmitting(false);
      return data as JobPosting;

    } catch (err: any) {
      console.error("Erro ao criar vaga:", err);
      setError(err.message || "Não foi possível criar a vaga. Tente novamente.");
      setIsSubmitting(false);
      return null;
    }
  };

  const updateJob = async (jobId: number): Promise<boolean> => {
    setIsSubmitting(true);
    setError(null);
    try {
      const updatedJobData = {
        "titulo": formData.jobTitle,
        "descricao": formData.jobDescription,
        "endereco": formData.endereco,
        "requisitos_obrigatorios": formData.requiredSkills,
        "requisitos_desejaveis": formData.desiredSkills,
      };

      const response = await fetch(`${API_BASE_URL}/api/jobs/${jobId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updatedJobData),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Não foi possível atualizar a vaga. Tente novamente.");
      }
      
      return true;
    } catch (err: any) {
      console.error("Erro ao atualizar vaga:", err);
      setError(err.message || "Não foi possível atualizar a vaga. Tente novamente.");
      return false;
    } finally {
      setIsSubmitting(false);
    }
  };

  const resetForm = () => {
    setFormData({
      jobTitle: '',
      jobDescription: '',
      endereco: '',
      requiredSkills: '',
      desiredSkills: ''
    });
  };

  return {
    formData,
    isSubmitting,
    error,
    updateField,
    submitJob,
    resetForm,
    setInitialData,
    updateJob,
  };
};