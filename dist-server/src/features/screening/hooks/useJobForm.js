// Local: src/features/screening/hooks/useJobForm.ts
import { useState, useCallback } from 'react';
// Remova: import { baserow } from '../../../shared/services/baserowClient'; // REMOVA esta linha
import { useAuth } from '../../auth/hooks/useAuth';
// Remova: const VAGAS_TABLE_ID = '709'; // REMOVA esta linha
export const useJobForm = () => {
    const { profile } = useAuth();
    const [formData, setFormData] = useState({
        jobTitle: '',
        jobDescription: '',
        endereco: '',
        requiredSkills: '',
        desiredSkills: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const updateField = (field, value) => {
        setFormData(prev => ({
            ...prev,
            [field]: value
        }));
    };
    const setInitialData = useCallback((data) => {
        setFormData(data);
    }, []);
    const submitJob = async () => {
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
                "usuario": [profile.id] // Envia o ID do usuário logado para associar
            };
            // Chame o backend para criar a vaga
            const response = await fetch('/api/jobs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newJobData),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Não foi possível criar a vaga. Tente novamente.");
            }
            setIsSubmitting(false);
            return data;
        }
        catch (err) {
            console.error("Erro ao criar vaga:", err);
            setError(err.message || "Não foi possível criar a vaga. Tente novamente.");
            setIsSubmitting(false);
            return null;
        }
    };
    const updateJob = async (jobId) => {
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
            // Chame o backend para atualizar a vaga
            const response = await fetch(`/api/jobs/${jobId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updatedJobData),
            });
            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || "Não foi possível atualizar a vaga. Tente novamente.");
            }
            return true;
        }
        catch (err) {
            console.error("Erro ao atualizar vaga:", err);
            setError(err.message || "Não foi possível atualizar a vaga. Tente novamente.");
            return false;
        }
        finally {
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
