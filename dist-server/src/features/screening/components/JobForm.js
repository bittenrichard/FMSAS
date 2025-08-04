// Local: src/features/screening/components/JobForm.tsx
import React from 'react';
const JobForm = ({ formData, onFieldChange, onSubmit, onCancel, isSubmitting = false, submitButtonText = 'Salvar e Enviar Currículos' }) => {
    const handleSubmit = (e) => {
        e.preventDefault();
        onSubmit();
    };
    return (<form className="space-y-6" onSubmit={handleSubmit}>
      <div>
        <label htmlFor="jobTitle" className="block text-sm font-medium text-gray-700">
          Título da Vaga
        </label>
        <input type="text" name="jobTitle" id="jobTitle" value={formData.jobTitle} onChange={(e) => onFieldChange('jobTitle', e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Ex: Desenvolvedor Frontend Sênior" required disabled={isSubmitting}/>
      </div>

      {/* --- NOVO CAMPO DE ENDEREÇO ADICIONADO AQUI --- */}
      <div>
        <label htmlFor="endereco" className="block text-sm font-medium text-gray-700">
          Endereço da Vaga
        </label>
        <input type="text" name="endereco" id="endereco" value={formData.endereco} onChange={(e) => onFieldChange('endereco', e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Ex: Av. Paulista, 1000, São Paulo - SP ou Remoto" required disabled={isSubmitting}/>
      </div>
      
      <div>
        <label htmlFor="jobDescription" className="block text-sm font-medium text-gray-700">
          Descrição Completa da Vaga
        </label>
        <textarea id="jobDescription" name="jobDescription" rows={6} value={formData.jobDescription} onChange={(e) => onFieldChange('jobDescription', e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Cole aqui a descrição da vaga..." required disabled={isSubmitting}/>
      </div>
      
      <div>
        <label htmlFor="requiredSkills" className="block text-sm font-medium text-gray-700">
          Requisitos Obrigatórios
        </label>
        <input type="text" name="requiredSkills" id="requiredSkills" value={formData.requiredSkills} onChange={(e) => onFieldChange('requiredSkills', e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Separe por vírgulas: React, TypeScript, Node.js..." required disabled={isSubmitting}/>
        <p className="mt-1 text-xs text-gray-500">
          Estes são os critérios principais que a IA usará para a pontuação.
        </p>
      </div>
      
      <div>
        <label htmlFor="desiredSkills" className="block text-sm font-medium text-gray-700">
          Requisitos Desejáveis (Opcional)
        </label>
        <input type="text" name="desiredSkills" id="desiredSkills" value={formData.desiredSkills} onChange={(e) => onFieldChange('desiredSkills', e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="Ex: Experiência com GraphQL, CI/CD..." disabled={isSubmitting}/>
      </div>
      
      <div className="flex justify-end pt-4">
        <button type="button" onClick={onCancel} className="bg-gray-200 text-gray-700 px-6 py-2 rounded-md hover:bg-gray-300 mr-3 transition-colors" disabled={isSubmitting}>
          Cancelar
        </button>
        <button type="submit" className="bg-indigo-600 text-white px-6 py-2 rounded-md hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed" disabled={isSubmitting}>
          {isSubmitting ? 'Salvando...' : submitButtonText}
        </button>
      </div>
    </form>);
};
export default JobForm;
