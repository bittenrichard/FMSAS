// Tipos para o fluxo de autenticação, agora mais genéricos

export interface UserProfile {
  id: number; // O ID numérico do Baserow
  nome: string;
  email: string;
  empresa: string;
  telefone: string | null;
  avatar_url: string | null;
  google_refresh_token?: string | null; // Adicionando o token de refresh
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface SignUpCredentials extends LoginCredentials {
  nome: string;
  empresa: string;
  telefone: string;
}

// O estado de autenticação agora guarda apenas o perfil do usuário
export interface AuthState {
  profile: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}