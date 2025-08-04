import React, { useState, useEffect } from 'react';
import { Upload, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';
const UpdateProfileForm = ({ profile, onProfileUpdate }) => {
    const [name, setName] = useState(profile.nome || '');
    const [company, setCompany] = useState(profile.empresa || '');
    const [avatarUrl, setAvatarUrl] = useState(profile.avatar_url || '');
    const [uploading, setUploading] = useState(false);
    const [successMessage, setSuccessMessage] = useState(null);
    const [errorMessage, setErrorMessage] = useState(null);
    useEffect(() => {
        setName(profile.nome || '');
        setCompany(profile.empresa || '');
        setAvatarUrl(profile.avatar_url || '');
    }, [profile]);
    const getAvatarFallback = (name) => {
        const displayName = name || '?';
        return `https://ui-avatars.com/api/?name=${encodeURIComponent(displayName)}&background=random&color=fff&bold=true`;
    };
    const handleProfileSubmit = async (e) => {
        e.preventDefault();
        setSuccessMessage(null);
        setErrorMessage(null);
        try {
            const updatedData = { nome: name, empresa: company };
            // Chame o backend para atualizar o perfil
            const response = await fetch(`/api/users/${profile.id}/profile`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updatedData),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Não foi possível atualizar o perfil. Tente novamente.');
            }
            setSuccessMessage('Perfil atualizado com sucesso!');
            onProfileUpdate(data.user); // O backend deve retornar o perfil atualizado
        }
        catch (error) {
            setErrorMessage(error.message || 'Não foi possível atualizar o perfil. Tente novamente.');
            console.error(error);
        }
    };
    const handleAvatarUpload = async (event) => {
        setUploading(true);
        setErrorMessage(null);
        setSuccessMessage(null);
        try {
            const file = event.target.files?.[0];
            if (!file)
                throw new Error("Nenhum arquivo selecionado.");
            if (file.size > 2 * 1024 * 1024) {
                throw new Error("O arquivo é muito grande. O limite é de 2MB.");
            }
            // ***** IMPORTANTE: A lógica de upload de arquivo precisa ser adaptada aqui *****
            // Você precisará enviar o arquivo para o SEU backend, que por sua vez,
            // irá chamar a API do Baserow para fazer o upload do arquivo.
            // O código atual envia diretamente se baserowClient for exposto, o que NÃO É SEGURO.
            // Exemplo de como você FARIA a chamada para o seu backend (AJUSTE NECESSÁRIO NO BACKEND):
            const formData = new FormData();
            formData.append('avatar', file); // 'avatar' é o nome do campo que seu backend espera
            formData.append('userId', String(profile.id)); // Envia o ID do usuário se o backend precisar para associar o avatar
            const response = await fetch('/api/upload-avatar', {
                method: 'POST',
                body: formData, // FormData não precisa de Content-Type manual
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Não foi possível enviar a foto. Tente novamente.");
            }
            const newAvatarUrl = data.avatar_url; // Seu backend retornaria a URL do avatar
            // A Baserow.patch no servidor já foi adicionada no endpoint de perfil.
            // Se o seu endpoint /api/upload-avatar já atualiza o perfil, não precisa de outra patch aqui.
            // Assumindo que o endpoint de upload retorna a URL do avatar e já atualiza o perfil no Baserow.
            setAvatarUrl(newAvatarUrl);
            onProfileUpdate({ avatar_url: newAvatarUrl });
            setSuccessMessage("Foto de perfil atualizada com sucesso!");
        }
        catch (error) {
            console.error("Erro no upload da foto:", error);
            setErrorMessage(error.message || "Não foi possível trocar a foto. Tente novamente.");
        }
        finally {
            setUploading(false);
        }
    };
    return (<div className="bg-white p-8 rounded-lg shadow-sm border border-gray-100">
      <h3 className="text-xl font-semibold mb-6 text-gray-800">Perfil Público</h3>

      {successMessage && (<div className="mb-4 flex items-center gap-2 rounded-md bg-green-50 p-3 text-sm text-green-700">
          <CheckCircle size={18}/> {successMessage}
        </div>)}
      {errorMessage && (<div className="mb-4 flex items-center gap-2 rounded-md bg-red-50 p-3 text-sm text-red-700">
          <AlertCircle size={18}/> {errorMessage}
        </div>)}

      <div className="flex items-center gap-6 mb-8">
        <img src={avatarUrl || getAvatarFallback(name)} alt="Avatar" className="h-24 w-24 rounded-full object-cover bg-gray-200"/>
        <div>
          <label htmlFor="avatar-upload" className={`cursor-pointer inline-flex items-center gap-2 px-4 py-2 bg-indigo-100 text-indigo-700 font-semibold rounded-md hover:bg-indigo-200 transition-colors ${uploading ? 'opacity-50 cursor-not-allowed' : ''}`}>
            {uploading ? (<Loader2 size={16} className="animate-spin"/>) : (<Upload size={16}/>)}
            {uploading ? 'Enviando...' : 'Trocar Foto'}
          </label>
          <input id="avatar-upload" type="file" accept="image/png, image/jpeg, image/gif" className="hidden" onChange={handleAvatarUpload} disabled={uploading}/>
          <p className="text-xs text-gray-500 mt-2">PNG, JPG, GIF até 2MB.</p>
        </div>
      </div>

      <form onSubmit={handleProfileSubmit} className="space-y-6">
        <div>
          <label htmlFor="name" className="block text-sm font-medium text-gray-700">Nome</label>
          <input id="name" type="text" value={name} onChange={(e) => setName(e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"/>
        </div>
        <div>
          <label htmlFor="company" className="block text-sm font-medium text-gray-700">Empresa</label>
          <input id="company" type="text" value={company} onChange={(e) => setCompany(e.target.value)} className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"/>
        </div>
        <div className="flex justify-end pt-2">
          <button type="submit" className="px-6 py-2 bg-indigo-600 text-white font-semibold rounded-md hover:bg-indigo-700 transition-colors">
            Salvar Alterações
          </button>
        </div>
      </form>
    </div>);
};
export default UpdateProfileForm;
