import { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
// O hook agora simplesmente consome o contexto.
// Qualquer componente que usar este hook receberá o estado compartilhado.
export const useAuth = () => {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth deve ser usado dentro de um AuthProvider');
    }
    return context;
};
