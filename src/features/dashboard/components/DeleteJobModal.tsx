import React from 'react';
import { X, AlertTriangle } from 'lucide-react';

interface DeleteJobModalProps {
  jobTitle: string;
  onClose: () => void;
  onConfirm: () => void;
  isDeleting: boolean;
}

const DeleteJobModal: React.FC<DeleteJobModalProps> = ({ jobTitle, onClose, onConfirm, isDeleting }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-50 p-4 transition-opacity duration-300">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md transform transition-all duration-300 scale-95 opacity-0 animate-scale-in">
        <div className="p-6">
          <div className="flex items-start">
            <div className="flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
              <AlertTriangle className="h-6 w-6 text-red-600" aria-hidden="true" />
            </div>
            <div className="ml-4 text-left">
              <h3 className="text-lg leading-6 font-bold text-gray-900">
                Excluir Triagem
              </h3>
              <div className="mt-2">
                <p className="text-sm text-gray-500">
                  Você tem certeza que deseja excluir a triagem para a vaga <span className="font-bold">"{jobTitle}"</span>?
                </p>
                <p className="mt-2 text-sm text-red-600">
                  Todos os candidatos associados a esta triagem serão perdidos. Esta ação não pode ser desfeita.
                </p>
              </div>
            </div>
          </div>
        </div>
        <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse rounded-b-lg">
          <button
            type="button"
            className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:ml-3 sm:w-auto sm:text-sm transition-colors disabled:opacity-50"
            onClick={onConfirm}
            disabled={isDeleting}
          >
            {isDeleting ? 'Excluindo...' : 'Confirmar Exclusão'}
          </button>
          <button
            type="button"
            className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:w-auto sm:text-sm transition-colors"
            onClick={onClose}
            disabled={isDeleting}
          >
            Cancelar
          </button>
        </div>
      </div>
      <style>{`
        @keyframes scale-in {
          from { transform: scale(0.95); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }
        .animate-scale-in {
          animation: scale-in 0.2s ease-out forwards;
        }
      `}</style>
    </div>
  );
};

export default DeleteJobModal;