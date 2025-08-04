// Local: src/shared/services/googleCalendarSyncService.ts
import { google } from 'googleapis';
import { baserowServer } from './baserowServerClient.js';
// --- CONSTANTES DE ID DE TABELAS ---
const USERS_TABLE_ID = '711';
const AGENDAMENTOS_TABLE_ID = '713';
// As credenciais do Google OAuth2Client (necessárias para gerar access tokens para as APIs)
// ATENÇÃO: Em produção, estas credenciais devem vir de variáveis de ambiente.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
// Instância do OAuth2Client
const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
/**
 * Busca o usuário do Baserow e define o refresh token no cliente OAuth2.
 * @param userId ID do usuário no Baserow.
 * @returns Profile do usuário.
 */
async function getUserAndSetCredentials(userId) {
    const user = await baserowServer.getRow(USERS_TABLE_ID, userId);
    if (!user || !user.google_refresh_token) {
        throw new Error('Usuário não encontrado ou não conectado ao Google Calendar.');
    }
    oauth2Client.setCredentials({ refresh_token: user.google_refresh_token });
    return user; // Garante a tipagem
}
/**
 * Processa uma notificação de exclusão de evento do Google Calendar.
 * Busca o evento no Baserow pelo google_event_id e o deleta.
 * @param googleEventId O ID do evento no Google Calendar.
 */
export async function handleGoogleEventDeleted(googleEventId) {
    try {
        console.log(`[GoogleSyncService] Tentando deletar evento do Baserow com google_event_id: ${googleEventId}`);
        // Busca o agendamento no Baserow que corresponde a este google_event_id
        // Assumindo que você tem um campo 'google_event_id' na sua tabela de Agendamentos
        const { results } = await baserowServer.get(AGENDAMENTOS_TABLE_ID, `?filter__google_event_id__equal=${googleEventId}`);
        if (results && results.length > 0) {
            const baserowEventId = results[0].id; // Pega o ID do registro no Baserow
            console.log(`[GoogleSyncService] Encontrado agendamento Baserow ID ${baserowEventId} para google_event_id: ${googleEventId}. Deletando...`);
            await baserowServer.delete(AGENDAMENTOS_TABLE_ID, baserowEventId);
            console.log(`[GoogleSyncService] Agendamento Baserow ID ${baserowEventId} deletado com sucesso.`);
        }
        else {
            console.warn(`[GoogleSyncService] Nenhum agendamento Baserow encontrado para google_event_id: ${googleEventId}. Ignorando exclusão.`);
        }
    }
    catch (error) {
        console.error(`[GoogleSyncService] Erro ao processar exclusão de evento Google (ID: ${googleEventId}):`, error);
        throw error; // Re-lança o erro para o chamador
    }
}
/**
 * Atualiza um evento no Baserow com o ID do Google Event.
 * Chamado após a criação bem-sucedida de um evento no Google Calendar.
 * @param baserowEventId O ID do evento no Baserow.
 * @param googleEventId O ID do evento no Google Calendar.
 */
export async function updateBaserowEventWithGoogleId(baserowEventId, googleEventId) {
    try {
        console.log(`[GoogleSyncService] Atualizando agendamento Baserow ID ${baserowEventId} com google_event_id: ${googleEventId}`);
        await baserowServer.patch(AGENDAMENTOS_TABLE_ID, baserowEventId, {
            google_event_id: googleEventId
        });
        console.log(`[GoogleSyncService] Agendamento Baserow ID ${baserowEventId} atualizado com o ID do Google.`);
    }
    catch (error) {
        console.error(`[GoogleSyncService] Erro ao atualizar Baserow com Google Event ID (${baserowEventId}, ${googleEventId}):`, error);
        throw error;
    }
}
// Futuramente: Funções para sincronização inicial (Google -> Baserow)
// export async function syncGoogleCalendarToBaserow(userId: number) { ... }
// Futuramente: Funções para processar notificações de criação/atualização
// export async function handleGoogleEventCreatedOrUpdated(notificationData: any) { ... }
