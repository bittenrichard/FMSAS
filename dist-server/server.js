// Local: server.ts
import dotenv from 'dotenv';
dotenv.config(); // Carrega o .env da raiz
import express from 'express';
import cors from 'cors';
import { google } from 'googleapis';
import { baserowServer } from './src/shared/services/baserowServerClient.js';
import fetch from 'node-fetch';
import bcrypt from 'bcryptjs';
import multer from 'multer';
const app = express();
const port = process.env.PORT || 3001;
const upload = multer();
// --- VALIDAÇÃO DE VARIÁVEIS DE AMBIENTE CRÍTICAS ---
if (!process.env.FRONTEND_URL) {
    console.error("ERRO CRÍTICO: A variável de ambiente FRONTEND_URL não está definida.");
    process.exit(1); // Encerra o processo se a URL do frontend não for encontrada
}
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REDIRECT_URI) {
    console.error("ERRO CRÍTICO: As credenciais do Google não foram encontradas no arquivo .env");
    process.exit(1);
}
// --- FIM DA VALIDAÇÃO ---
// ATUALIZAÇÃO: Usa a origem diretamente, sem fallback para localhost.
// O servidor irá falhar ao iniciar se a variável não estiver presente.
const corsOptions = {
    origin: '*'
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const oauth2Client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
// Armazenamento temporário de tokens (em um cenário de produção, use um banco de dados como Redis)
const userTokens = {};
app.get('/', (req, res) => {
    res.send('FMSAS API is running!');
});
app.get('/api/users/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const { data } = await baserowServer.database.rows.get('users', Number(userId));
        res.json(data);
    }
    catch (error) {
        console.error('Failed to fetch user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});
app.patch('/api/users/:userId/profile', async (req, res) => {
    const { userId } = req.params;
    const { name, email } = req.body;
    try {
        // Atualiza no Baserow
        const { data } = await baserowServer.database.rows.update('users', Number(userId), {
            "nome": name,
            "email": email
        });
        res.json({ message: 'Profile updated successfully', user: data });
    }
    catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});
app.patch('/api/users/:userId/password', async (req, res) => {
    const { userId } = req.params;
    const { currentPassword, newPassword } = req.body;
    try {
        const { data: user } = await baserowServer.database.rows.get('users', Number(userId));
        const isMatch = await bcrypt.compare(currentPassword, user.senha);
        if (!isMatch) {
            return res.status(400).json({ error: "Senha atual incorreta." });
        }
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await baserowServer.database.rows.update('users', Number(userId), {
            'senha': hashedNewPassword
        });
        res.json({ message: "Senha atualizada com sucesso." });
    }
    catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ error: "Erro ao atualizar a senha." });
    }
});
app.post('/api/upload-avatar', upload.single('avatar'), async (req, res) => {
    const { userId } = req.body;
    if (!req.file) {
        return res.status(400).send('Nenhum arquivo enviado.');
    }
    try {
        const response = await baserowServer.userFiles.uploadFile(req.file);
        const fileUrl = response.data.url;
        // Atualize a linha do usuário na tabela 'users' com a URL do avatar
        await baserowServer.database.rows.update('users', Number(userId), {
            'avatar_url': fileUrl
        });
        res.json({ message: 'Avatar uploaded successfully', url: fileUrl });
    }
    catch (error) {
        console.error('Error uploading avatar:', error);
        res.status(500).json({ error: 'Failed to upload avatar' });
    }
});
// Rota para iniciar o processo de autenticação Google
app.get('/api/google/auth/connect', (req, res) => {
    const { userId } = req.query;
    if (!userId || typeof userId !== 'string') {
        return res.status(400).send('userId é obrigatório.');
    }
    const scopes = [
        'https://www.googleapis.com/auth/calendar'
    ];
    const authorizationUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        include_granted_scopes: true,
        state: userId, // Passa o userId no 'state' para recuperá-lo no callback
        prompt: 'consent'
    });
    res.json({ authorizationUrl });
});
// Rota de callback do Google
app.get('/api/google/auth/callback', async (req, res) => {
    const { code, state } = req.query;
    const userId = state;
    if (!code) {
        return res.status(400).send('Código de autorização não encontrado.');
    }
    if (!userId) {
        return res.status(400).send('userId não encontrado no estado.');
    }
    try {
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        // Salvar o refresh_token no Baserow para o usuário correspondente
        await baserowServer.database.rows.update('users', parseInt(userId, 10), {
            'google_refresh_token': tokens.refresh_token
        });
        // Redireciona de volta para a página de configurações no frontend
        res.redirect(`${process.env.FRONTEND_URL}/dashboard/settings?google_auth=success`);
    }
    catch (err) {
        console.error('Erro ao obter token do Google:', err.message);
        res.status(500).send('Falha na autenticação com o Google.');
    }
});
app.get('/api/google/auth/status', async (req, res) => {
    const { userId } = req.query;
    if (!userId || typeof userId !== 'string') {
        return res.status(400).send('userId é obrigatório.');
    }
    try {
        const { data } = await baserowServer.database.rows.get('users', parseInt(userId, 10));
        const hasToken = !!data.google_refresh_token; // Verifica se o campo não está vazio
        res.json({ isConnected: hasToken });
    }
    catch (error) {
        console.error('Erro ao verificar status de conexão com Google:', error);
        res.status(500).json({ error: 'Erro ao verificar status de conexão.' });
    }
});
app.post('/api/google/auth/disconnect', async (req, res) => {
    const { userId } = req.body;
    if (!userId) {
        return res.status(400).json({ error: 'userId é obrigatório.' });
    }
    try {
        const { data: user } = await baserowServer.database.rows.get('users', Number(userId));
        const refreshToken = user.google_refresh_token;
        if (refreshToken) {
            // Revoga o token no Google
            await oauth2Client.revokeToken(refreshToken);
        }
        // Limpa o token no Baserow
        await baserowServer.database.rows.update('users', Number(userId), {
            'google_refresh_token': null // ou ""
        });
        res.json({ message: 'Desconectado do Google com sucesso.' });
    }
    catch (error) {
        console.error('Erro ao desconectar do Google:', error);
        res.status(500).json({ error: 'Falha ao desconectar do Google.' });
    }
});
// Rota para criar um evento no Google Calendar
app.post('/api/google/calendar/create-event', async (req, res) => {
    const { userId, eventDetails } = req.body;
    if (!userId || !eventDetails) {
        return res.status(400).json({ error: 'userId e eventDetails são obrigatórios.' });
    }
    try {
        const { data: user } = await baserowServer.database.rows.get('users', parseInt(userId, 10));
        const refreshToken = user.google_refresh_token;
        if (!refreshToken) {
            return res.status(401).json({ error: 'Usuário não conectado ao Google. Por favor, conecte-se primeiro.' });
        }
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const calendar = google.calendar({ version: 'v3', auth: oauth2Client });
        const event = {
            summary: eventDetails.summary,
            description: eventDetails.description,
            start: {
                dateTime: eventDetails.startDateTime,
                timeZone: 'America/Sao_Paulo',
            },
            end: {
                dateTime: eventDetails.endDateTime,
                timeZone: 'America/Sao_Paulo',
            },
            attendees: eventDetails.attendees,
            reminders: {
                useDefault: false,
                overrides: [
                    { method: 'email', 'minutes': 24 * 60 },
                    { method: 'popup', 'minutes': 10 },
                ],
            },
        };
        const createdEvent = await calendar.events.insert({
            calendarId: 'primary',
            requestBody: event,
            sendUpdates: 'all' // notifica os convidados por email
        });
        res.status(201).json({ message: 'Evento criado com sucesso!', data: createdEvent.data });
    }
    catch (error) {
        console.error('Erro ao criar evento no Google Calendar:', error.message);
        if (error.response && error.response.data) {
            console.error('Detalhes do erro do Google:', error.response.data.error);
        }
        res.status(500).json({ error: 'Falha ao criar evento no Google Calendar.' });
    }
});
// Rotas da aplicação
app.get('/api/jobs', async (req, res) => {
    try {
        const { data } = await baserowServer.database.rows.list('jobs');
        res.json(data.results);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});
app.post('/api/jobs', async (req, res) => {
    try {
        const { data } = await baserowServer.database.rows.create('jobs', req.body);
        res.status(201).json(data);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to create job' });
    }
});
app.patch('/api/jobs/:jobId', async (req, res) => {
    try {
        const { jobId } = req.params;
        const { data } = await baserowServer.database.rows.update('jobs', Number(jobId), req.body);
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to update job' });
    }
});
app.delete('/api/jobs/:jobId', async (req, res) => {
    try {
        const { jobId } = req.params;
        await baserowServer.database.rows.delete('jobs', Number(jobId));
        res.status(204).send();
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to delete job' });
    }
});
app.get('/api/candidates', async (req, res) => {
    try {
        const { data } = await baserowServer.database.rows.list('candidates');
        res.json(data.results);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to fetch candidates' });
    }
});
app.patch('/api/candidates/:candidateId/status', async (req, res) => {
    const { candidateId } = req.params;
    const { statusId } = req.body; // e.g., { statusId: 443423 }
    if (!statusId) {
        return res.status(400).json({ error: "O 'statusId' é obrigatório." });
    }
    try {
        const { data } = await baserowServer.database.rows.update('candidates', Number(candidateId), {
            'status': [{ id: statusId }]
        });
        res.json(data);
    }
    catch (error) {
        console.error(`Erro ao atualizar status do candidato ${candidateId}:`, error);
        res.status(500).json({ error: 'Falha ao atualizar o status do candidato.' });
    }
});
app.get('/api/data/all/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const [jobsResponse, candidatesResponse] = await Promise.all([
            baserowServer.database.rows.list('jobs', { filters: { "filter_type": "AND", "filters": [{ "type": "link_row_has", "field": "usuario", "value": userId }] } }),
            baserowServer.database.rows.list('candidates', { filters: { "filter_type": "AND", "filters": [{ "type": "link_row_has", "field": "usuario", "value": userId }] } })
        ]);
        res.json({
            jobs: jobsResponse.data.results,
            candidates: candidatesResponse.data.results
        });
    }
    catch (error) {
        console.error("Erro ao buscar todos os dados:", error);
        res.status(500).json({ error: 'Failed to fetch all data' });
    }
});
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }
    try {
        // 1. Verificar se o usuário já existe
        const { data: existingUsers } = await baserowServer.database.rows.list('users', {
            filters: {
                filter_type: "AND",
                filters: [{
                        type: "equal",
                        field: "email",
                        value: email
                    }]
            }
        });
        if (existingUsers.count > 0) {
            return res.status(409).json({ error: "Este e-mail já está em uso." });
        }
        // 2. Hash da senha
        const hashedPassword = await bcrypt.hash(password, 10);
        // 3. Criar novo usuário no Baserow
        const { data: newUser } = await baserowServer.database.rows.create('users', {
            "nome": name,
            "email": email,
            "senha": hashedPassword
        });
        // Remover a senha da resposta
        const { senha, ...userProfile } = newUser;
        res.status(201).json({ message: "Usuário criado com sucesso!", user: userProfile });
    }
    catch (error) {
        console.error("Erro no cadastro:", error);
        res.status(500).json({ error: "Ocorreu um erro interno no servidor." });
    }
});
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data: users } = await baserowServer.database.rows.list('users', {
            filters: {
                filter_type: "AND",
                filters: [{ type: "equal", field: "email", value: email }]
            }
        });
        if (users.count === 0) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }
        const user = users.results[0];
        const isPasswordCorrect = await bcrypt.compare(password, user.senha);
        if (!isPasswordCorrect) {
            return res.status(401).json({ error: "Credenciais inválidas." });
        }
        const { senha, ...userProfile } = user;
        res.json({ message: "Login bem-sucedido!", user: userProfile });
    }
    catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ error: "Ocorreu um erro interno no servidor." });
    }
});
// Rota de Webhook para o n8n
app.post('/api/n8n/webhook/schedule', async (req, res) => {
    const { candidateEmail, candidateName, summary, description, startDateTime, endDateTime } = req.body;
    const n8nWebhookUrl = process.env.N8N_SCHEDULE_WEBHOOK_URL;
    if (!n8nWebhookUrl) {
        console.error("A URL do webhook do n8n não está configurada.");
        return res.status(500).json({ error: "Serviço de agendamento indisponível." });
    }
    try {
        await fetch(n8nWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                candidateEmail,
                candidateName,
                summary,
                description,
                startDateTime,
                endDateTime
            }),
        });
        res.status(200).json({ message: 'Solicitação de agendamento enviada.' });
    }
    catch (error) {
        console.error("Erro ao acionar webhook do n8n:", error);
        res.status(500).json({ error: "Falha ao enviar solicitação de agendamento." });
    }
});
app.post('/api/upload-curriculums', upload.array('curriculums'), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'Nenhum currículo enviado.' });
    }
    const files = req.files;
    const { jobId, userId } = req.body;
    if (!jobId || !userId) {
        return res.status(400).json({ error: 'jobId e userId são obrigatórios.' });
    }
    try {
        const uploadPromises = files.map(file => {
            const formData = new FormData();
            formData.append('file', new Blob([file.buffer]), file.originalname);
            return fetch(`${process.env.N8N_FILE_UPLOAD_URL}?jobId=${jobId}&userId=${userId}`, {
                method: 'POST',
                body: `${formData}`,
            });
        });
        const responses = await Promise.all(uploadPromises);
        // Verificar se todos os uploads foram bem-sucedidos
        const allOk = responses.every(response => response.ok);
        if (allOk) {
            res.status(200).json({ message: `${files.length} currículos enviados para processamento.` });
        }
        else {
            // Tenta extrair mensagens de erro das respostas que falharam
            const errorMessages = await Promise.all(responses
                .filter(r => !r.ok)
                .map(r => r.text()));
            console.error("Erros no upload para o n8n:", errorMessages);
            throw new Error(`Falha ao enviar alguns arquivos. Detalhes: ${errorMessages.join(', ')}`);
        }
    }
    catch (error) {
        console.error('Erro ao enviar currículos para o n8n:', error);
        res.status(500).json({ error: `Falha ao processar os currículos. ${error.message}` });
    }
});
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
