// Local: src/App.tsx

import React, { useEffect, useCallback, useState } from 'react';
import { useAuth } from './features/auth/hooks/useAuth';
import { useNavigation } from './shared/hooks/useNavigation';
import LoginPage from './features/auth/components/LoginPage';
import SignUpPage from './features/auth/components/SignUpPage';
import MainLayout from './shared/components/Layout/MainLayout';
import DashboardPage from './features/dashboard/components/DashboardPage';
import NewScreeningPage from './features/screening/components/NewScreeningPage';
import EditScreeningPage from './features/screening/components/EditScreeningPage';
import ResultsPage from './features/results/components/ResultsPage';
import SettingsPage from './features/settings/components/SettingsPage';
import { LoginCredentials, SignUpCredentials } from './features/auth/types';
import { JobPosting } from './features/screening/types';
import { Candidate } from './shared/types';
import { Loader2 } from 'lucide-react';
import CandidateDatabasePage from './features/database/components/CandidateDatabasePage';
import AgendaPage from './features/agenda/components/AgendaPage';
import { useDataStore } from './shared/store/useDataStore';

// IMPORTAÇÕES DO DndProvider e HTML5Backend
import { DndProvider } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';

const LoadingSpinner: React.FC = () => (
  <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50"><div className="text-center"><Loader2 className="mx-auto h-12 w-12 text-indigo-600 animate-spin" /><h2 className="mt-6 text-xl font-semibold text-gray-800">Carregando...</h2><p className="mt-2 text-gray-500">Estamos preparando tudo para você.</p></div></div>
);

function App() {
  const { profile, isAuthenticated, isLoading: isAuthLoading, error: authError, signIn, signOut, signUp } = useAuth();
  const { currentPage, navigateTo } = useNavigation(isAuthenticated ? 'dashboard' : 'login');
  
  const { jobs, candidates, isDataLoading, fetchAllData, deleteJobById, updateJobInStore } = useDataStore();
  
  const [selectedJob, setSelectedJob] = useState<JobPosting | null>(null);

  useEffect(() => {
    if (isAuthenticated && profile) {
      fetchAllData(profile);
    }
  }, [isAuthenticated, profile, fetchAllData]);

  const handleLogin = async (credentials: LoginCredentials) => {
    if (await signIn(credentials)) {
      navigateTo('dashboard');
    }
  };

  const handleSignUp = async (credentials: SignUpCredentials) => {
    const newUser = await signUp(credentials);
    if (newUser) {
      await handleLogin({ email: credentials.email, password: credentials.password });
    }
  };

  const handleLogout = () => {
    signOut();
    navigateTo('login');
  };

  const handleViewResults = (job: JobPosting) => {
    setSelectedJob(job);
    navigateTo('results');
  };

  const handleEditJob = (job: JobPosting) => {
    setSelectedJob(job);
    navigateTo('edit-screening');
  };

  const handleJobCreated = (newJob: JobPosting) => {
    useDataStore.getState().addJob(newJob);
    setSelectedJob(newJob);
    navigateTo('results');
  };

  const handleJobUpdated = (updatedJob: JobPosting) => {
    useDataStore.getState().updateJobInStore(updatedJob);
    navigateTo('dashboard');
  };

  const handleDeleteJob = async (jobId: number) => {
    try {
      await deleteJobById(jobId);
    } catch (error) {
      console.error("Erro ao deletar vaga:", error);
      alert("Não foi possível excluir a vaga.");
    }
  };

  if (isAuthLoading) return <LoadingSpinner />;
  if (!isAuthenticated) {
    return (
      <div className="font-inter antialiased">
        {currentPage === 'signup' ? <SignUpPage onSignUp={handleSignUp} onNavigateLogin={() => navigateTo('login')} isLoading={isAuthLoading} error={authError} /> : <LoginPage onLogin={handleLogin} onNavigateSignUp={() => navigateTo('signup')} isLoading={isAuthLoading} error={authError} />}
      </div>
    );
  }
  if (!profile || isDataLoading) return <LoadingSpinner />;

  const renderContent = () => {
    switch (currentPage) {
      case 'dashboard': return <DashboardPage jobs={jobs} candidates={candidates} onViewResults={handleViewResults} onDeleteJob={handleDeleteJob} onNavigate={navigateTo} onEditJob={handleEditJob} />;
      case 'new-screening': return <NewScreeningPage onJobCreated={handleJobCreated} onCancel={() => navigateTo('dashboard')} />;
      case 'edit-screening':
        if (!selectedJob) return <div>Vaga não encontrada!</div>;
        return <EditScreeningPage jobToEdit={selectedJob} onJobUpdated={handleJobUpdated} onCancel={() => navigateTo('dashboard')} />;
      case 'results': return <ResultsPage selectedJob={selectedJob} candidates={candidates} onDataSynced={() => fetchAllData(profile)} />;
      case 'settings': return <SettingsPage />;
      case 'database': return <CandidateDatabasePage />;
      case 'agenda': return <AgendaPage />;
      default: return <DashboardPage jobs={jobs} candidates={candidates} onViewResults={handleViewResults} onDeleteJob={handleDeleteJob} onNavigate={navigateTo} onEditJob={handleEditJob} />;
    }
  };

  return (
    <div className="font-inter antialiased">
      {/* CORREÇÃO: Envolva a aplicação com o DndProvider */}
      <DndProvider backend={HTML5Backend}>
        <MainLayout currentPage={currentPage} user={profile} onNavigate={navigateTo} onLogout={handleLogout}>{renderContent()}</MainLayout>
      </DndProvider>
    </div>
  );
}
export default App;