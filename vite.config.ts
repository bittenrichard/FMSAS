import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Redireciona /api para o nosso backend na porta 3001
      '/api': {
        target: 'http://localhost:3001', 
        changeOrigin: true,
      },
    },
  },
});