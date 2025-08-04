// Local: src/features/screening/components/EditScreeningPage.tsx
import React, { useEffect } from 'react';
import JobForm from './JobForm';
import { useJobForm } from '../hooks/useJobForm';
const EditScreeningPage = ({ jobToEdit, onJobUpdated, onCancel }) => {
    // Passamos os dados iniciais para o nosso hook do formulário
    const { formData, isSubmitting, error, updateField, setInitialData, updateJob } = useJobForm();
    // Quando o componente for montado, preenchemos o formulário com os dados da vaga
    useEffect(() => {
        if (jobToEdit) {
            setInitialData({
                jobTitle: jobToEdit.titulo,
                jobDescription: jobToEdit.descricao,
                requiredSkills: jobToEdit.requisitos_obrigatorios,
                desiredSkills: jobToEdit.requisitos_desejaveis,
            });
        }
    }, [jobToEdit, setInitialData]);
    const handleSubmit = async () => {
        const success = await updateJob(jobToEdit.id);
        if (success) {
            onJobUpdated();
        }
    };
    return (<div className="fade-in">
      <div className="bg-white p-8 rounded-lg shadow-sm max-w-4xl mx-auto">
        <h3 className="text-2xl font-semibold mb-6">Editar Triagem de Vaga</h3>
        {error && (<div className="mb-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-md text-sm" role="alert">
                <p>{error}</p>
            </div>)}
        <JobForm formData={formData} onFieldChange={updateField} onSubmit={handleSubmit} onCancel={onCancel} isSubmitting={isSubmitting} submitButtonText="Salvar Alterações" // Texto do botão personalizado
    />
      </div>
    </div>);
};
export default EditScreeningPage;
