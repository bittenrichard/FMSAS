// Local: src/shared/hooks/useGoogleAuth.ts
import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../../features/auth/hooks/useAuth';
const hasGoogleToken = (profile) => {
    return !!profile && !!profile.google_refresh_token;
};
export const useGoogleAuth = () => {
    const { profile, updateProfile, refetchProfile } = useAuth();
    const [isGoogleConnected, setIsGoogleConnected] = useState(hasGoogleToken(profile));
    // Usamos uma referência para controlar se estamos no meio de um processo de autenticação
    const isConnecting = useRef(false);
    useEffect(() => {
        setIsGoogleConnected(hasGoogleToken(profile));
    }, [profile]);
    // --- INÍCIO DA NOVA LÓGICA DE 'FOCUS' ---
    useEffect(() => {
        // Esta função será chamada sempre que o usuário voltar para esta aba/janela
        const handleFocus = () => {
            // Se a janela ganhou foco e nós estávamos no meio de uma conexão com o Google...
            if (isConnecting.current) {
                console.log("[useGoogleAuth] Janela principal recuperou o foco. Verificando status da conexão...");
                // ... então, buscamos o perfil atualizado.
                refetchProfile();
                // E resetamos a flag para não buscar novamente sem necessidade.
                isConnecting.current = false;
            }
        };
        // Adiciona o "ouvinte" de foco à janela
        window.addEventListener('focus', handleFocus);
        // Remove o "ouvinte" quando o componente for desmontado para evitar vazamentos de memória
        return () => {
            window.removeEventListener('focus', handleFocus);
        };
    }, [refetchProfile]);
    // --- FIM DA NOVA LÓGICA DE 'FOCUS' ---
    const connectGoogleCalendar = useCallback(async () => {
        if (!profile) {
            alert('Você precisa estar logado para conectar sua agenda.');
            return;
        }
        try {
            const response = await fetch(`/api/google/auth/connect?userId=${profile.id}`);
            if (!response.ok)
                throw new Error('Falha ao obter URL de autenticação.');
            const { url } = await response.json();
            if (url) {
                // 1. Ativa a nossa flag de que um processo de conexão foi iniciado
                isConnecting.current = true;
                // 2. Abre o popup
                window.open(url, '_blank', 'width=600,height=700,noopener,noreferrer');
            }
        }
        catch (error) {
            console.error('Erro ao iniciar conexão com Google:', error);
            alert('Não foi possível iniciar a conexão com o Google Calendar. Tente novamente.');
        }
    }, [profile]);
    const disconnectGoogleCalendar = useCallback(async () => {
        if (!profile)
            return;
        try {
            await fetch('/api/google/auth/disconnect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId: profile.id }),
            });
            const updatedProfile = { ...profile, google_refresh_token: null };
            updateProfile(updatedProfile);
        }
        catch (error) {
            console.error('Erro ao desconectar do Google:', error);
            alert('Não foi possível desconectar a conta do Google.');
        }
    }, [profile, updateProfile]);
    return {
        isGoogleConnected,
        connectGoogleCalendar,
        disconnectGoogleCalendar,
    };
};
