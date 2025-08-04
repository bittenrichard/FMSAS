import React from 'react';
import { Menu } from 'lucide-react'; // Ícone de menu
const Header = ({ currentPage, onToggleMobileMenu }) => {
    const getPageTitle = () => {
        switch (currentPage) {
            case 'dashboard': return 'Dashboard';
            case 'new-screening': return 'Nova Triagem';
            case 'results': return 'Resultados da Triagem';
            case 'database': return 'Banco de Talentos';
            case 'settings': return 'Configurações';
            default: return 'Recruta.AI';
        }
    };
    return (<header className="flex items-center h-20 px-6 sm:px-10 bg-white shadow-sm flex-shrink-0 z-10">
      {/* Botão do Menu Mobile */}
      <button onClick={onToggleMobileMenu} className="md:hidden mr-4 text-gray-600 hover:text-indigo-600" aria-label="Abrir menu">
        <Menu size={28}/>
      </button>

      <h1 className="text-2xl font-semibold text-gray-800">
        {getPageTitle()}
      </h1>
    </header>);
};
export default Header;
