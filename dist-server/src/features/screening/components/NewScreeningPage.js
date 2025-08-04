import React from 'react';
import JobForm from './JobForm';
import { useJobForm } from '../hooks/useJobForm';
const NewScreeningPage = ({ onJobCreated, onCancel }) => {
    const { formData, isSubmitting, error, updateField, submitJob, resetForm } = useJobForm();
    const handleSubmit = async () => {
        const newJob = await submitJob();
        if (newJob) {
            resetForm();
            onJobCreated(newJob);
        }
    };
    const handleCancel = () => {
        resetForm();
        onCancel();
    };
    return (<div className="fade-in">
      <div className="bg-white p-8 rounded-lg shadow-sm max-w-4xl mx-auto">
        <h3 className="text-2xl font-semibold mb-6">Criar Nova Triagem de Vaga</h3>
        {error && (<div className="mb-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-md text-sm" role="alert">
                <p>{error}</p>
            </div>)}
        <JobForm formData={formData} onFieldChange={updateField} onSubmit={handleSubmit} onCancel={handleCancel} isSubmitting={isSubmitting}/>
      </div>
    </div>);
};
export default NewScreeningPage;
