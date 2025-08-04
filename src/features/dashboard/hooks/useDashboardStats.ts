import { useMemo } from 'react';
import { JobPosting } from '../../screening/types';
import { Candidate } from '../../results/types';

export interface DashboardStats {
  activeJobs: number;
  totalCandidates: number;
  averageScore: number;
  approvedCandidates: number;
}

export const useDashboardStats = (jobs: JobPosting[], candidates: Candidate[]) => {
  const stats: DashboardStats = useMemo(() => {
    const activeJobs = jobs.length;

    // --- CORREÇÃO 1: Considerar apenas candidatos das vagas que existem atualmente ---
    // Criamos um conjunto com os IDs das vagas ativas para uma checagem rápida.
    const activeJobIds = new Set(jobs.map(job => job.id));
    
    // Filtramos a lista geral de candidatos para manter apenas aqueles cujas vagas ainda existem.
    const activeCandidates = candidates.filter(candidate =>
        candidate.vaga && candidate.vaga.some(v => activeJobIds.has(v.id))
    );

    // A partir de agora, todos os cálculos usarão esta lista filtrada e correta de candidatos.
    const totalCandidates = activeCandidates.length;

    const approvedCandidates = activeCandidates.filter(
      (c) => c.score && Number(c.score) >= 90
    ).length;

    let averageScore = 0;
    if (totalCandidates > 0) {
      // --- CORREÇÃO 2: Forçar a conversão do score para número antes de somar ---
      // Isso previne o erro de concatenação de texto.
      const totalScore = activeCandidates.reduce((acc, curr) => acc + (Number(curr.score) || 0), 0);
      averageScore = Math.round(totalScore / totalCandidates);
    }

    return {
      activeJobs,
      totalCandidates,
      averageScore,
      approvedCandidates,
    };
  }, [jobs, candidates]);

  return { stats };
};