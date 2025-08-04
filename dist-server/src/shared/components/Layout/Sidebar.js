import React from 'react';
import { LayoutDashboard, PlusCircle, Settings, LogOut, ChevronsLeft, ChevronsRight, Database, Calendar } from 'lucide-react';
const getAvatarFallback = (name) => {
    const displayName = name || '?';
    return `https://ui-avatars.com/api/?name=${encodeURIComponent(displayName)}&background=indigo&color=fff&bold=true`;
};
const Sidebar = ({ currentPage, onNavigate, onLogout, user, isCollapsed, onToggle, isMobileOpen, onCloseMobile }) => {
    const menuItems = [
        { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { key: 'new-screening', label: 'Nova Triagem', icon: PlusCircle },
        { key: 'database', label: 'Banco de Talentos', icon: Database },
        { key: 'agenda', label: 'Agenda', icon: Calendar },
        { key: 'settings', label: 'Configurações', icon: Settings }
    ];
    const handleNavigate = (page) => {
        onNavigate(page);
        onCloseMobile();
    };
    return (<div className={`
      fixed inset-y-0 left-0 z-30 flex flex-col bg-white
      transform transition-transform duration-300 ease-in-out
      ${isMobileOpen ? 'translate-x-0 shadow-xl' : '-translate-x-full'}
      md:relative md:translate-x-0 md:shadow-none md:rounded-r-xl
      ${isCollapsed ? 'w-20' : 'w-64'}
    `}>
      
      <div className="flex items-center justify-center h-20 flex-shrink-0">
        <h1 className="text-2xl font-bold text-gray-800 overflow-hidden">
          {isCollapsed ? (<span className="text-indigo-600">R.</span>) : (<>Recruta.<span className="text-indigo-600">AI</span></>)}
        </h1>
      </div>

      <nav className="flex-grow p-4 space-y-2">
        {menuItems.map((item) => (<button key={item.key} onClick={() => handleNavigate(item.key)} className={`flex items-center w-full p-3 rounded-lg font-medium transition-all duration-200 ${currentPage === item.key ? 'text-white bg-indigo-600 shadow-md' : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'} ${isCollapsed ? 'justify-center' : ''}`} title={item.label}>
            <item.icon className={isCollapsed ? '' : 'mr-3'} size={20}/>
            {!isCollapsed && <span>{item.label}</span>}
          </button>))}
      </nav>

      <div className="p-2 border-t border-gray-100">
        <div className={`flex items-center w-full p-2 rounded-lg`}>
          <img src={user?.avatar_url || getAvatarFallback(user?.nome || null)} alt="avatar" className="h-10 w-10 rounded-full object-cover flex-shrink-0 bg-indigo-100"/>
          {!isCollapsed && (<div className="ml-3 overflow-hidden">
              <p className="font-semibold text-sm text-gray-800 truncate">{user?.nome}</p>
              <p className="text-xs text-gray-500 truncate">{user?.empresa}</p>
            </div>)}
        </div>

        <button onClick={onLogout} className={`flex items-center w-full p-3 mt-1 text-gray-600 hover:bg-gray-100 hover:text-gray-900 rounded-lg font-medium transition-colors ${isCollapsed ? 'justify-center' : ''}`} title="Sair">
          <LogOut className={isCollapsed ? '' : 'mr-3'} size={20}/>
          {!isCollapsed && <span>Sair</span>}
        </button>
        
        <button onClick={onToggle} className={`hidden md:flex items-center w-full p-3 mt-1 text-gray-600 hover:bg-gray-100 hover:text-gray-900 rounded-lg font-medium transition-colors ${isCollapsed ? 'justify-center' : ''}`} title={isCollapsed ? "Expandir menu" : "Recolher menu"}>
          {isCollapsed ? <ChevronsRight size={20}/> : <ChevronsLeft size={20}/>}
        </button>
      </div>
    </div>);
};
export default Sidebar;
