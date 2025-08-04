/**
 * Formata um número de telefone para o padrão de link do WhatsApp (com código do país).
 * @param phone O número de telefone a ser formatado.
 * @returns O número formatado ou null se a entrada for inválida.
 */
export const formatPhoneNumberForWhatsApp = (phone: string | null): string | null => {
    if (!phone) return null;
    // Remove todos os caracteres que não são dígitos
    const digitsOnly = phone.replace(/\D/g, '');
    
    // Se o número tem 11 dígitos (DDD + 9 + número), assume que é do Brasil (55)
    if (digitsOnly.length === 11) {
      return `55${digitsOnly}`;
    }
    // Se já tem 13 (código do país + DDD + número), retorna como está
    if (digitsOnly.length === 13) {
      return digitsOnly;
    }
    // Retorna nulo se o formato não for reconhecido
    return null; 
  };