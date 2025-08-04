// Local: src/features/results/components/ResultsPage.tsx
import React, { useState, useEffect, useMemo } from 'react';
import { LayoutGrid, List, UploadCloud } from 'lucide-react';
import UploadArea from './UploadArea';
import CandidateTable from './CandidateTable';
import KanbanBoard from './KanbanBoard';
import { useAuth } from '../../auth/hooks/useAuth';
import CandidateDetailModal from './CandidateDetailModal';
import ScheduleModal from '../../agenda/components/ScheduleModal';
import { useGoogleAuth } from '../../../shared/hooks/useGoogleAuth';
import { useDataStore } from '../../../shared/store/useDataStore';
import UploadModal from './UploadModal';
const ResultsPage = ({ selectedJob, candidates, onDataSynced }) => {
    const { profile } = useAuth();
    const { isGoogleConnected } = useGoogleAuth();
    const { updateCandidateStatusInStore, fetchAllData } = useDataStore();
    const [viewMode, setViewMode] = useState('kanban');
    const [jobCandidates, setJobCandidates] = useState([]);
    const [isProcessing, setIsProcessing] = useState(false);
    const [uploadSuccessMessage, setUploadSuccessMessage] = useState(null);
    const [uploadError, setUploadError] = useState(null);
    const [selectedCandidate, setSelectedCandidate] = useState(null);
    const [isScheduleModalOpen, setIsScheduleModalOpen] = useState(false);
    const [candidateToSchedule, setCandidateToSchedule] = useState(null);
    const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
    const [sortConfig, setSortConfig] = useState({ key: 'score', direction: 'descending' });
    const sortedJobCandidates = useMemo(() => {
        let filtered = selectedJob ? candidates.filter(c => c.vaga && c.vaga.some(v => v.id === selectedJob.id)) : [];
        if (sortConfig.key) {
            filtered.sort((a, b) => {
                const aValue = a[sortConfig.key] || '';
                const bValue = b[sortConfig.key] || '';
                if (typeof aValue === 'string' && typeof bValue === 'string') {
                    return sortConfig.direction === 'ascending'
                        ? aValue.localeCompare(bValue)
                        : bValue.localeCompare(aValue);
                }
                if (typeof aValue === 'number' && typeof bValue === 'number') {
                    return sortConfig.direction === 'ascending'
                        ? aValue - bValue
                        : bValue - aValue;
                }
                return 0;
            });
        }
        return filtered;
    }, [selectedJob, candidates, sortConfig]);
    useEffect(() => {
        setJobCandidates(sortedJobCandidates);
    }, [sortedJobCandidates]);
    const handleRequestSort = (key) => {
        let direction = 'ascending';
        if (sortConfig.key === key && sortConfig.direction === 'ascending') {
            direction = 'descending';
        }
        setSortConfig({ key, direction });
    };
    const handleUpdateCandidateStatus = async (candidateId, newStatus) => {
        updateCandidateStatusInStore(candidateId, newStatus);
        try {
            const response = await fetch(`/api/candidates/${candidateId}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus }),
            });
            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || "Não foi possível atualizar o status.");
            }
        }
        catch (error) {
            console.error("Erro ao atualizar status do candidato:", error);
            alert("Não foi possível atualizar o status. Revertendo alteração.");
            if (profile)
                fetchAllData(profile);
        }
    };
    const handleFilesSelected = async (files) => {
        // NOVO: Logs para depuração no frontend
        console.log("handleFilesSelected: Iniciando upload...");
        console.log("Selected Job:", selectedJob);
        console.log("Profile:", profile);
        console.log("Files received:", files);
        console.log("Number of files:", files.length);
        if (!selectedJob || !profile) {
            setUploadError('Vaga ou perfil de usuário não selecionados.');
            console.error("Erro: Vaga ou perfil de usuário ausentes.");
            return;
        }
        if (!files || files.length === 0) {
            setUploadError('Nenhum arquivo selecionado para upload.');
            console.error("Erro: Nenhum arquivo selecionado.");
            return;
        }
        setIsProcessing(true);
        setUploadError(null);
        setUploadSuccessMessage(null);
        try {
            const formData = new FormData();
            Array.from(files).forEach(file => {
                formData.append('curriculumFiles', file);
            });
            formData.append('jobId', String(selectedJob.id));
            formData.append('userId', String(profile.id));
            // NOVO: Log dos dados do FormData (apenas chaves, conteúdo de FileList não pode ser logado diretamente)
            for (const pair of formData.entries()) {
                console.log(`FormData entry - ${pair[0]}:`, pair[1]);
            }
            const response = await fetch('/api/upload-curriculums', {
                method: 'POST',
                body: formData,
                // Remover Content-Type ao usar FormData, o navegador define automaticamente.
                // headers: { 'Content-Type': 'application/json' }, // <-- REMOVA esta linha se estiver presente
            });
            const data = await response.json();
            if (!response.ok) {
                console.error("Erro na resposta do servidor:", response.status, data);
                throw new Error(data.error || 'Ocorreu um erro durante o upload.');
            }
            if (data.success) {
                setUploadSuccessMessage(data.message);
                onDataSynced();
                console.log("Upload bem-sucedido:", data);
            }
            else {
                setUploadError(data.message);
                console.error("Upload falhou com mensagem do servidor:", data.message);
            }
        }
        catch (error) {
            setUploadError(error.message || 'Ocorreu um erro desconhecido durante o upload.');
            console.error("Erro na requisição de upload:", error);
        }
        finally {
            setIsProcessing(false);
        }
    };
    const handleScheduleSubmit = async (details) => {
        if (!candidateToSchedule || !selectedJob || !profile)
            return;
        setIsProcessing(true);
        try {
            const response = await fetch('/api/google/calendar/create-event', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userId: profile.id,
                    eventData: details,
                    candidate: candidateToSchedule,
                    job: selectedJob
                }),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || "Não foi possível agendar a entrevista.");
            }
            setUploadSuccessMessage("Entrevista agendada com sucesso!");
            onDataSynced();
        }
        catch (error) {
            console.error("Falha ao criar agendamento:", error);
            setUploadError(error.message || "Não foi possível agendar a entrevista.");
        }
        finally {
            setIsProcessing(false);
            setIsScheduleModalOpen(false);
            setCandidateToSchedule(null);
        }
    };
    const handleViewDetails = (candidate) => setSelectedCandidate(candidate);
    const handleCloseDetailModal = () => setSelectedCandidate(null);
    const handleOpenScheduleModal = (candidate) => {
        if (!isGoogleConnected) {
            alert("Conecte sua conta Google em 'Configurações' para agendar.");
            return;
        }
        setCandidateToSchedule(candidate);
        setIsScheduleModalOpen(true);
    };
    if (!selectedJob)
        return <div className="p-10 text-center"><h3 className="text-xl font-semibold">Nenhuma vaga selecionada</h3></div>;
    return (<>
      <div className="fade-in h-full flex flex-col">
        {/* CABEÇALHO FIXO */}
        <div className="flex-shrink-0">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-2xl font-semibold">Resultados: {selectedJob.titulo}</h3>
              <p className="text-gray-600">Arraste e solte os candidatos para gerenciar o fluxo.</p>
            </div>
            <div className="flex items-center gap-2 p-1 bg-gray-100 rounded-lg">
              <button onClick={() => setViewMode('table')} className={`p-2 rounded-md transition-colors ${viewMode === 'table' ? 'bg-white shadow text-indigo-600' : 'text-gray-500 hover:bg-gray-200'}`}><List size={20}/></button>
              <button onClick={() => setViewMode('kanban')} className={`p-2 rounded-md transition-colors ${viewMode === 'kanban' ? 'bg-white shadow text-indigo-600' : 'text-gray-500 hover:bg-gray-200'}`}><LayoutGrid size={20}/></button>
              
              {/* NOVO BOTÃO DE UPLOAD PARA O MODO KANBAN */}
              {viewMode === 'kanban' && (<button onClick={() => setIsUploadModalOpen(true)} className="flex items-center justify-center gap-2 px-4 py-2 text-sm font-semibold rounded-md hover:bg-indigo-700 transition-colors bg-indigo-600 text-white">
                  <UploadCloud size={18}/>
                  Enviar Currículo
                </button>)}
            </div>
          </div>
          {/* A área de upload antiga (grande) só aparece no modo de tabela */}
          {viewMode === 'table' && (<>
              {uploadSuccessMessage && <div className="mt-4 p-3 bg-green-50 text-green-700 rounded-md">{uploadSuccessMessage}</div>}
              {uploadError && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{uploadError}</div>}
              <div className="mt-6">
                <UploadArea onFilesSelected={handleFilesSelected} isUploading={isProcessing}/>
              </div>
            </>)}
        </div>
        <div className="flex-1 mt-6 min-h-0 overflow-y-auto hide-scrollbar">
          {viewMode === 'table' ? (<div className="h-full">
              <CandidateTable candidates={jobCandidates} onViewDetails={handleViewDetails} requestSort={handleRequestSort} sortConfig={sortConfig}/>
            </div>) : (<KanbanBoard candidates={jobCandidates} onUpdateStatus={handleUpdateCandidateStatus} onViewDetails={handleViewDetails} onScheduleInterview={handleOpenScheduleModal}/>)}
        </div>
      </div>
      {selectedCandidate && (<CandidateDetailModal candidate={selectedCandidate} onClose={handleCloseDetailModal} onScheduleInterview={handleOpenScheduleModal} onUpdateStatus={handleUpdateCandidateStatus}/>)}
      <ScheduleModal isOpen={isScheduleModalOpen} onClose={() => setIsScheduleModalOpen(false)} candidate={candidateToSchedule} onSchedule={handleScheduleSubmit}/>
      <UploadModal isOpen={isUploadModalOpen} onClose={() => {
            setIsUploadModalOpen(false);
            setUploadSuccessMessage(null);
            setUploadError(null);
        }} onFilesSelected={handleFilesSelected} isUploading={isProcessing} successMessage={uploadSuccessMessage} errorMessage={uploadError}/>
    </>);
};
export default ResultsPage;
