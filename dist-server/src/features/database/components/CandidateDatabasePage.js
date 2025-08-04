// Local: src/features/database/components/CandidateDatabasePage.tsx
import React, { useState, useMemo, useEffect } from 'react';
import { useAuth } from '../../auth/hooks/useAuth';
import { Loader2, FilterX, Filter, ChevronDown, Eye, MessageCircle } from 'lucide-react';
import CandidateDetailModal from '../../results/components/CandidateDetailModal';
import { formatPhoneNumberForWhatsApp } from '../../../shared/utils/formatters'; // <-- CORRIGIDO: Removido '}' extra e o 's'
import { useDataStore } from '../../../shared/store/useDataStore';
const sexOptions = ['Masculino', 'Feminino', 'Outro'];
const escolaridadeOptions = [
    'Ensino fundamental incompleto', 'Ensino fundamental completo',
    'Ensino médio incompleto', 'Ensino médio completo',
    'Superior incompleto', 'Superior completo',
    'Pós-graduação', 'Mestrado', 'Doutorado',
];
const LoadingSpinner = () => (<div className="flex flex-col items-center justify-center h-full py-10">
        <Loader2 className="h-12 w-12 text-indigo-600 animate-spin"/>
        <h2 className="mt-4 text-xl font-semibold text-gray-800">Carregando Talentos...</h2>
    </div>);
const CandidateDatabasePage = () => {
    const { profile } = useAuth();
    const { candidates: allCandidatesFromStore, isDataLoading, fetchAllData } = useDataStore();
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedVaga, setSelectedVaga] = useState('');
    const [selectedSexo, setSelectedSexo] = useState('');
    const [selectedEscolaridade, setSelectedEscolaridade] = useState('');
    const [minIdade, setMinIdade] = useState('');
    const [maxIdade, setMaxIdade] = useState('');
    const [showFilters, setShowFilters] = useState(true);
    const [vagas, setVagas] = useState([]);
    const [selectedCandidate, setSelectedCandidate] = useState(null);
    useEffect(() => {
        console.log("Banco de Talentos: allCandidatesFromStore (brutos):", allCandidatesFromStore);
        const uniqueVagas = [...new Set(allCandidatesFromStore.flatMap(c => c.vaga?.map(v => v.value) || []).filter(Boolean))].sort();
        setVagas(uniqueVagas);
    }, [allCandidatesFromStore]);
    const filteredCandidates = useMemo(() => {
        const filtered = allCandidatesFromStore.filter(candidate => {
            const searchLower = searchTerm.toLowerCase();
            const nameMatch = searchTerm ? candidate.nome.toLowerCase().includes(searchLower) : true;
            const vagaMatch = selectedVaga
                ? (candidate.vaga && candidate.vaga.some(v => v.value === selectedVaga))
                : true;
            const sexoMatch = selectedSexo
                ? (candidate.sexo && candidate.sexo.toLowerCase() === selectedSexo.toLowerCase())
                : true;
            const escolaridadeMatch = selectedEscolaridade
                ? (candidate.escolaridade && candidate.escolaridade.toLowerCase() === selectedEscolaridade.toLowerCase())
                : true;
            const minIdadeNum = minIdade ? parseInt(minIdade) : 0;
            const maxIdadeNum = maxIdade ? parseInt(maxIdade) : Infinity;
            const idadeMatch = (minIdade === '' || (candidate.idade !== undefined && candidate.idade !== null && Number(candidate.idade) >= minIdadeNum)) &&
                (maxIdade === '' || (candidate.idade !== undefined && candidate.idade !== null && Number(candidate.idade) <= maxIdadeNum));
            return nameMatch && vagaMatch && sexoMatch && escolaridadeMatch && idadeMatch;
        });
        console.log("Banco de Talentos: filteredCandidates (após filtros):", filtered);
        return filtered;
    }, [allCandidatesFromStore, searchTerm, selectedVaga, selectedSexo, selectedEscolaridade, minIdade, maxIdade]);
    const clearFilters = () => {
        setSearchTerm('');
        setSelectedVaga('');
        setSelectedSexo('');
        setSelectedEscolaridade('');
        setMinIdade('');
        setMaxIdade('');
    };
    const activeFilterCount = [searchTerm, selectedVaga, selectedSexo, selectedEscolaridade, minIdade, maxIdade].filter(Boolean).length;
    if (isDataLoading)
        return <LoadingSpinner />;
    return (<>
            <div className="fade-in">
                <div className="flex justify-between items-center mb-6">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900 mb-1">Banco de Talentos</h1>
                        <p className="text-gray-600">Pesquise e reaproveite candidatos de processos seletivos anteriores.</p>
                    </div>
                    <button onClick={() => setShowFilters(!showFilters)} className="flex items-center gap-2 px-4 py-2 bg-white text-gray-700 font-semibold rounded-md hover:bg-gray-50 border border-gray-300 transition-colors shadow-sm">
                        <Filter size={18} className="text-indigo-600"/>
                        <span>Filtros</span>
                        {activeFilterCount > 0 && (<span className="bg-indigo-600 text-white text-xs font-bold rounded-full h-5 w-5 flex items-center justify-center">{activeFilterCount}</span>)}
                        <ChevronDown size={18} className={`transition-transform duration-300 ${showFilters ? 'rotate-180' : ''}`}/>
                    </button>
                </div>

                {showFilters && (<div className="mb-8 bg-white p-6 rounded-lg shadow-md border border-gray-200">
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Buscar por nome</label>
                                <input type="text" placeholder="Nome do candidato..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="w-full text-sm border-gray-300 rounded-md"/>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Vaga</label>
                                <select value={selectedVaga} onChange={e => setSelectedVaga(e.target.value)} className="w-full text-sm border-gray-300 rounded-md">
                                    <option value="">Todas</option>
                                    {vagas.map(vaga => <option key={vaga} value={vaga}>{vaga}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Sexo</label>
                                <select value={selectedSexo} onChange={e => setSelectedSexo(e.target.value)} className="w-full text-sm border-gray-300 rounded-md">
                                    <option value="">Todos</option>
                                    {sexOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                                </select>
                            </div>
                             <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Escolaridade</label>
                                <select value={selectedEscolaridade} onChange={e => setSelectedEscolaridade(e.target.value)} className="w-full text-sm border-gray-300 rounded-md">
                                    <option value="">Todas</option>
                                    {escolaridadeOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                                </select>
                            </div>
                            <div className="flex items-end gap-2 col-span-2 sm:col-span-1">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">Idade Mín.</label>
                                    <input type="number" placeholder="Ex: 25" value={minIdade} onChange={e => setMinIdade(e.target.value)} className="w-full text-sm border-gray-300 rounded-md"/>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">Idade Máx.</label>
                                    <input type="number" placeholder="Ex: 40" value={maxIdade} onChange={e => setMaxIdade(e.target.value)} className="w-full text-sm border-gray-300 rounded-md"/>
                                </div>
                            </div>
                        </div>
                        <div className="flex justify-end mt-4">
                            <button onClick={clearFilters} className="flex items-center gap-2 text-sm text-gray-600 hover:text-indigo-600 font-medium transition-colors">
                                <FilterX size={16}/> Limpar Filtros
                            </button>
                        </div>
                    </div>)}

                <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-100">
                     <h3 className="text-xl font-bold text-gray-800 mb-6">
                        {activeFilterCount > 0 ? `Candidatos Encontrados (${filteredCandidates.length})` : `Todos os Candidatos (${allCandidatesFromStore.length})`}
                    </h3>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                           <thead>
                                <tr className="text-xs text-gray-500 uppercase border-b bg-gray-50">
                                    <th className="px-4 py-3 font-semibold">Candidato</th>
                                    <th className="px-4 py-3 font-semibold">Vaga Original</th>
                                    <th className="px-4 py-3 font-semibold">Score</th>
                                    <th className="px-4 py-3 font-semibold">Contato</th>
                                    <th className="px-4 py-3 font-semibold text-center">Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredCandidates.length > 0 ? (filteredCandidates.map((candidate) => {
            const whatsappNumber = formatPhoneNumberForWhatsApp(candidate.telefone);
            return (<tr key={candidate.id} className="border-b hover:bg-gray-50 transition-colors">
                                                <td className="px-4 py-4 font-medium text-gray-800">{candidate.nome}</td>
                                                <td className="px-4 py-4 text-gray-600">{candidate.vaga && candidate.vaga[0] ? candidate.vaga[0].value : 'N/A'}</td>
                                                <td className="px-4 py-4 font-bold text-indigo-600">{candidate.score || 0}%</td>
                                                <td className="px-4 py-4 text-gray-600">{candidate.telefone || 'Não informado'}</td>
                                                <td className="px-4 py-4">
                                                    <div className="flex items-center justify-center space-x-2">
                                                        <button onClick={() => setSelectedCandidate(candidate)} className="p-2 text-gray-500 hover:bg-gray-200 hover:text-indigo-600 rounded-full transition-colors" title="Ver Detalhes">
                                                            <Eye size={18}/>
                                                        </button>
                                                        <a href={whatsappNumber ? `https://wa.me/${whatsappNumber}` : undefined} target="_blank" rel="noopener noreferrer" onClick={(e) => !whatsappNumber && e.preventDefault()} className={`p-2 rounded-full transition-colors ${!whatsappNumber ? 'text-gray-300 cursor-not-allowed' : 'text-gray-500 hover:bg-green-100 hover:text-green-600'}`} title={whatsappNumber ? 'Chamar no WhatsApp' : 'Telefone não disponível'}>
                                                            <MessageCircle size={18}/>
                                                        </a>
                                                    </div>
                                                </td>
                                            </tr>);
        })) : (<tr>
                                        <td colSpan={5} className="text-center py-10 text-gray-500">
                                            {activeFilterCount > 0 ? 'Nenhum candidato encontrado com os filtros aplicados.' : 'Nenhum talento no banco de dados ainda.'}
                                        </td>
                                    </tr>)}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            {selectedCandidate && (<CandidateDetailModal candidate={selectedCandidate} onClose={() => setSelectedCandidate(null)}/>)}
        </>);
};
export default CandidateDatabasePage;
