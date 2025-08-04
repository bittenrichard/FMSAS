import { useState, useCallback } from 'react'; // 1. Importar o useCallback
import { PageKey } from '../types';

export const useNavigation = (initialPage: PageKey = 'login') => {
  const [currentPage, setCurrentPage] = useState<PageKey>(initialPage);

  // 2. Envolvemos a função em 'useCallback'.
  // Isso garante que a função não seja recriada a cada renderização, quebrando o loop.
  const navigateTo = useCallback((page: PageKey) => {
    setCurrentPage(page);
  }, []); // O array de dependências vazio significa que ela nunca mudará.

  return {
    currentPage,
    navigateTo
  };
};