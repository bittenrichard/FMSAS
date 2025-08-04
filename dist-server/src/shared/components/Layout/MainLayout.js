// Local: src/shared/components/Layout/MainLayout.tsx
import React, { useState } from 'react'; // LINHA CORRIGIDA
import Sidebar from './Sidebar';
import Header from './Header';
const MainLayout = ({ currentPage, user, onNavigate, onLogout, children }) => {
    const [isSidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [isMobileMenuOpen, setMobileMenuOpen] = useState(false);
    const toggleSidebar = () => setSidebarCollapsed(!isSidebarCollapsed);
    const toggleMobileMenu = () => setMobileMenuOpen(!isMobileMenuOpen);
    const isFullHeightPage = currentPage === 'results' || currentPage === 'agenda' || currentPage === 'database';
    return (<div className="flex h-screen bg-gray-100 overflow-hidden">
      <Sidebar currentPage={currentPage} onNavigate={onNavigate} onLogout={onLogout} user={user} isCollapsed={isSidebarCollapsed} onToggle={toggleSidebar} isMobileOpen={isMobileMenuOpen} onCloseMobile={() => setMobileMenuOpen(false)}/>
      <div className="flex flex-col flex-grow relative overflow-hidden">
        {isMobileMenuOpen && (<div className="fixed inset-0 bg-black opacity-50 z-20 md:hidden" onClick={() => setMobileMenuOpen(false)}></div>)}
        <Header currentPage={currentPage} onToggleMobileMenu={toggleMobileMenu}/>
        <main className={`flex-grow p-6 sm:p-10 ${isFullHeightPage ? 'overflow-hidden' : 'overflow-y-auto'}`}>
          {children}
        </main>
      </div>
    </div>);
};
export default MainLayout;
