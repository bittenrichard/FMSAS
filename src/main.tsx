import React from 'react'; // Alterado de { StrictMode } para React
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { AuthProvider } from './features/auth/context/AuthContext.tsx';

import 'react-phone-input-2/lib/style.css';

createRoot(document.getElementById('root')!).render(
  // <React.StrictMode> {/* Abertura do StrictMode comentada */}
    <AuthProvider>
      <App />
    </AuthProvider>
  // </React.StrictMode> {/* Fechamento do StrictMode comentado */}
);