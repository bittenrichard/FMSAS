// Caminho: /src/shared/services/webhookService.ts

import { Candidate } from "../../features/results/types";
import { JobPosting } from "../../features/screening/types";
import { baserow } from "./baserowClient";

const VAGAS_TABLE_ID = '709';

export interface WebhookResponse {
  success: boolean;
  message: string;
  newCandidates?: Candidate[];
}

export const sendCurriculumsToWebhook = async (
  files: FileList, jobId: number, userId: number
): Promise<WebhookResponse> => {
  // ... (código existente do sendCurriculumsToWebhook)
};

export interface ScheduleWebhookPayload {
  candidateName: string;
  candidateEmail?: string;
  jobTitle: string;
  startTime: string;
  endTime: string;
  details: string;
  recruiterEmail: string;
}

export const sendScheduleToWebhook = async (payload: ScheduleWebhookPayload): Promise<{success: boolean}> => {
  const webhookUrl = 'https://webhook.focoserv.com.br/webhook/googleacesso';

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`Erro do Webhook! Status: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('Erro ao enviar agendamento para o webhook:', error);
    throw new Error('Falha ao comunicar com o serviço de agendamento.');
  }
};