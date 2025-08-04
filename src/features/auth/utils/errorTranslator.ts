/**
 * Traduz as mensagens de erro comuns do Supabase Auth para português.
 * @param errorMessage A mensagem de erro original em inglês.
 * @returns A mensagem de erro traduzida e amigável.
 */
export const translateSupabaseError = (errorMessage: string | undefined): string => {
  if (!errorMessage) {
    return 'Ocorreu um erro inesperado. Tente novamente.';
  }

  // Usamos um switch para mapear cada erro conhecido para sua tradução
  switch (errorMessage) {
    case 'Invalid login credentials':
      return 'E-mail ou senha inválidos. Por favor, verifique e tente novamente.';
    
    case 'User already registered':
      return 'Este e-mail já está cadastrado. Tente fazer login ou use um e-mail diferente.';

    case 'Password should be at least 6 characters':
      return 'Sua senha deve ter no mínimo 6 caracteres.';

    case 'Unable to validate email address: invalid format':
      return 'O formato do e-mail é inválido. Verifique o endereço digitado.';
    
    // Adicione outros casos de erro aqui conforme eles aparecerem

    default:
      // Para erros que ainda não mapeamos, retornamos uma mensagem genérica
      return 'Ocorreu um erro durante a autenticação. Por favor, tente novamente mais tarde.';
  }
};