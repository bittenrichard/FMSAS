// Caminho: /src/shared/services/webhookService.ts
const VAGAS_TABLE_ID = '709';
export const sendCurriculumsToWebhook = async (files, jobId, userId) => {
    // ... (código existente do sendCurriculumsToWebhook)
};
export const sendScheduleToWebhook = async (payload) => {
    const webhookUrl = 'https://webhook.focoserv.com.br/webhook/googleacesso';
    try {
        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!response.ok)
            throw new Error(`Erro do Webhook! Status: ${response.status}`);
        return await response.json();
    }
    catch (error) {
        console.error('Erro ao enviar agendamento para o webhook:', error);
        throw new Error('Falha ao comunicar com o serviço de agendamento.');
    }
};
