// Local: src/features/results/components/UploadModal.tsx

import React from 'react';
import { X, UploadCloud } from 'lucide-react';
import UploadArea from './UploadArea';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onFilesSelected: (files: FileList) => Promise<void>;
  isUploading?: boolean;
  successMessage: string | null;
  errorMessage: string | null;
}

const UploadModal: React.FC<UploadModalProps> = ({ 
  isOpen, 
  onClose, 
  onFilesSelected, 
  isUploading = false,
  successMessage,
  errorMessage,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-50 p-4 transition-opacity duration-300">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg transform transition-all duration-300 scale-95 opacity-0 animate-scale-in">
        <div className="flex justify-between items-center p-4 border-b bg-gray-50 rounded-t-lg">
          <h2 className="text-xl font-bold text-gray-800">Enviar Currículos</h2> {/* TEXTO ALTERADO AQUI */}
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800 transition-colors">
            <X size={24} />
          </button>
        </div>
        
        <div className="p-6">
          {successMessage && (
            <div className="mb-4 p-3 bg-green-50 text-green-700 rounded-md">
              {successMessage}
            </div>
          )}
          {errorMessage && (
            <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md">
              {errorMessage}
            </div>
          )}
          <UploadArea 
            onFilesSelected={onFilesSelected} 
            isUploading={isUploading} 
          />
        </div>
        
        <div className="bg-gray-50 px-6 py-3 flex justify-end rounded-b-lg">
          <button type="button" onClick={onClose} disabled={isUploading} className="mr-3 bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50">
            Fechar
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

export default UploadModal;