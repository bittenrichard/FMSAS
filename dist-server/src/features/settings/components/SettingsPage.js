// Local: src/features/settings/components/SettingsPage.tsx
import React from 'react'; // Não precisamos mais do useEffect aqui
import UpdateProfileForm from './UpdateProfileForm';
import UpdatePasswordForm from './UpdatePasswordForm';
import { useAuth } from '../../auth/hooks/useAuth';
import { useGoogleAuth } from '../../../shared/hooks/useGoogleAuth';
import { CheckCircle, Zap } from 'lucide-react';
const SettingsPage = () => {
    // A lógica da URL foi removida, o hook agora cuida de tudo
    const { profile, updateProfile } = useAuth();
    const { isGoogleConnected, connectGoogleCalendar, disconnectGoogleCalendar } = useGoogleAuth();
    const handleProfileUpdate = (newProfileData) => {
        updateProfile(newProfileData);
    };
    if (!profile) {
        return <div>Carregando perfil...</div>;
    }
    return (<div className="fade-in max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 mb-8">Configurações da Conta</h1>
            
            <div className="bg-white p-8 rounded-lg shadow-sm border border-gray-100 mb-8">
              <h3 className="text-xl font-semibold mb-4 text-gray-800">Integrações</h3>
              <div className="flex justify-between items-center">
                <div>
                    <p className="font-medium text-gray-700">Google Calendar</p>
                    <p className="text-sm text-gray-500">Agende entrevistas diretamente na sua agenda.</p>
                </div>
                {isGoogleConnected ? (<div className="text-center">
                        <div className="flex items-center gap-2 text-green-600 font-semibold">
                            <CheckCircle size={20}/> Conectado
                        </div>
                        <button onClick={disconnectGoogleCalendar} className="text-xs text-red-500 hover:underline mt-1">
                            Desconectar
                        </button>
                    </div>) : (<button onClick={connectGoogleCalendar} className="flex items-center gap-2 bg-blue-500 text-white font-bold py-2 px-4 rounded-lg hover:bg-blue-600 transition-colors">
                        <Zap size={16}/> Conectar
                    </button>)}
              </div>
            </div>

            <UpdateProfileForm profile={profile} onProfileUpdate={handleProfileUpdate}/>
            <UpdatePasswordForm />
        </div>);
};
export default SettingsPage;
