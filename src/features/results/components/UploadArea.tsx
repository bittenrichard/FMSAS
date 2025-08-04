import React, { useCallback } from 'react';
import { UploadCloud, Loader2 } from 'lucide-react';

interface UploadAreaProps {
  onFilesSelected: (files: FileList) => void;
  isUploading?: boolean;
}

const UploadArea: React.FC<UploadAreaProps> = ({ 
  onFilesSelected, 
  isUploading = false,
}) => {
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    if (isUploading) return;
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      onFilesSelected(files);
    }
  }, [onFilesSelected, isUploading]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      onFilesSelected(files);
    }
  };

  return (
    <div 
      className={`relative bg-white p-8 rounded-lg shadow-sm border-2 border-dashed text-center mb-8 transition-colors ${
        isUploading 
          ? 'border-indigo-300 bg-indigo-50 cursor-wait' 
          : 'border-gray-300 hover:border-indigo-400'
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
    >
      {isUploading ? (
        <div className="w-full max-w-md mx-auto">
          <Loader2 className="mx-auto text-indigo-600 animate-spin mb-4" size={40} />
          <h4 className="mt-4 text-lg font-semibold text-indigo-800">
            Analisando currículos...
          </h4>
          <p className="text-indigo-600">
            Isso pode levar alguns minutos. Aguarde a resposta final.
          </p>
        </div>
      ) : (
        <>
          <UploadCloud className="mx-auto text-gray-400" size={48} />
          <h4 className="mt-4 text-lg font-semibold text-gray-700">
            Arraste e solte os currículos aqui
          </h4>
          <p className="text-gray-500">ou</p>
          <label className="mt-4 inline-block">
            <input
              type="file"
              multiple
              accept=".pdf,.docx,.doc"
              onChange={handleFileSelect}
              className="hidden"
              disabled={isUploading}
            />
            <span className="px-4 py-2 bg-indigo-50 text-indigo-700 font-semibold rounded-md hover:bg-indigo-100 transition-colors cursor-pointer">
              Selecione os arquivos
            </span>
          </label>
          <p className="mt-2 text-xs text-gray-500">Formatos suportados: PDF, DOCX</p>
        </>
      )}
    </div>
  );
};

export default UploadArea;