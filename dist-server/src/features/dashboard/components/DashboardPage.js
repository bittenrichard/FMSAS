// Local: src/features/dashboard/components/DashboardPage.tsx
import React, { useState, useMemo } from 'react';
import StatCard from './StatCard';
import RecentScreenings from './RecentScreenings';
import { useDashboardStats } from '../hooks/useDashboardStats';
import ApprovedCandidatesModal from './ApprovedCandidatesModal';
import DeleteJobModal from './DeleteJobModal';
const DashboardPage = ({ jobs, candidates, onViewResults, onDeleteJob, onNavigate, onEditJob, // <-- NOVA PROP
 }) => {
    const { stats } = useDashboardStats(jobs, candidates);
    const [searchTerm, setSearchTerm] = useState('');
    const [isApprovedModalOpen, setIsApprovedModalOpen] = useState(false);
    const [jobToDelete, setJobToDelete] = useState(null);
    const [isDeleting, setIsDeleting] = useState(false);
    const approvedCandidates = useMemo(() => {
        const activeJobIds = new Set(jobs.map(job => job.id));
        return candidates.filter(c => c.score && c.score >= 90 &&
            c.vaga && c.vaga.some(v => activeJobIds.has(v.id)));
    }, [jobs, candidates]);
    const filteredJobs = useMemo(() => {
        const jobsWithStats = jobs.map(job => {
            const jobCandidates = candidates.filter(c => c.vaga && c.vaga.some(v => v.id === job.id));
            const candidateCount = jobCandidates.length;
            let averageScore = 0;
            if (candidateCount > 0) {
                const totalScore = jobCandidates.reduce((acc, curr) => acc + (Number(curr.score) || 0), 0);
                averageScore = Math.round(totalScore / candidateCount);
            }
            return { ...job, candidateCount, averageScore };
        });
        if (!searchTerm)
            return jobsWithStats;
        return jobsWithStats.filter(job => job.titulo.toLowerCase().includes(searchTerm.toLowerCase()));
    }, [jobs, candidates, searchTerm]);
    const statsData = [
        { title: 'Vagas Ativas', value: stats.activeJobs, iconName: 'briefcase', iconColor: 'text-indigo-600', iconBg: 'bg-indigo-100' },
        { title: 'Candidatos Triados', value: stats.totalCandidates, iconName: 'users', iconColor: 'text-green-600', iconBg: 'bg-green-100' },
        { title: 'Score de Compatibilidade', value: `${stats.averageScore}%`, iconName: 'check', iconColor: 'text-blue-600', iconBg: 'bg-blue-100' },
        { title: 'Aprovados (>90%)', value: stats.approvedCandidates, iconName: 'award', iconColor: 'text-amber-600', iconBg: 'bg-amber-100', onClick: () => setIsApprovedModalOpen(true) }
    ];
    const handleOpenDeleteModal = (job) => {
        setJobToDelete(job);
    };
    const handleCloseDeleteModal = () => {
        setJobToDelete(null);
    };
    const handleConfirmDelete = async () => {
        if (jobToDelete) {
            setIsDeleting(true);
            await onDeleteJob(jobToDelete.id);
            setIsDeleting(false);
            setJobToDelete(null);
        }
    };
    return (<>
      <div className="fade-in">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
          {statsData.map((stat, index) => <StatCard key={index} {...stat}/>)}
        </div>
        <RecentScreenings jobs={filteredJobs} onViewResults={onViewResults} onOpenDeleteModal={handleOpenDeleteModal} onEditJob={onEditJob} // <-- PASSANDO A PROP ADIANTE
     onNewScreening={() => onNavigate('new-screening')} searchTerm={searchTerm} setSearchTerm={setSearchTerm}/>
      </div>
      
      {isApprovedModalOpen && (<ApprovedCandidatesModal candidates={approvedCandidates} isLoading={false} onClose={() => setIsApprovedModalOpen(false)}/>)}

      {jobToDelete && (<DeleteJobModal jobTitle={jobToDelete.titulo} onClose={handleCloseDeleteModal} onConfirm={handleConfirmDelete} isDeleting={isDeleting}/>)}
    </>);
};
export default DashboardPage;
