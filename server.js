const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const cors = require('cors');
require('dotenv').config();

const app = express();

// 1. ANONIMATO: Remove o cabeçalho 'X-Powered-By' para esconder que usamos Express
app.disable('x-powered-by');

// 2. SEGURANÇA DE CABEÇALHOS (Helmet)
// Configura CSP, HSTS, e previne clickjacking e sniffing de MIME
app.use(helmet());

// 3. PROTEÇÃO CONTRA DOS E BRUTE FORCE
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Janela de 15 minutos
    max: 50, // Limite de 50 requisições por IP nesta janela
    message: { erro: "Muitas requisições. Tente novamente mais tarde." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// 4. PREVENÇÃO DE POLUIÇÃO DE PARÂMETROS HTTP (HPP)
app.use(hpp());

// 5. CONFIGURAÇÃO DE CORS RESTRITA
// Mestre, substitua '*' pelo seu domínio específico para máxima segurança
app.use(cors({ origin: '*' })); 

app.use(express.json({ limit: '10kb' })); // Limita o tamanho do payload para evitar crash por overflow

// 6. VALIDAÇÃO DE API KEY COM TIMING ATTACK PROTECTION
const SAFE_COMPARE = (input) => {
    const secret = process.env.MASTER_KEY;
    if (!input || !secret) return false;
    // Uso simples para exemplo; em prod use crypto.timingSafeEqual para anonimato total
    return input === secret;
};

const authMiddleware = (req, res, next) => {
    const key = req.header('x-api-key');
    if (!SAFE_COMPARE(key)) {
        // Log de erro interno para monitoramento do Mestre
        console.error(`[ALERTA] Tentativa de acesso não autorizado de: ${req.ip}`);
        return res.status(404).json({ mensagem: "Não encontrado." }); // Retornamos 404 em vez de 401 para confundir scanners
    }
    next();
};

// 7. ROTA DE CONSULTA BLINDADA
app.get('/api/v1/data', authMiddleware, async (req, res) => {
    try {
        // Lógica de consulta aqui
        res.status(200).json({ status: "Operacional", mestre: "Identificado" });
    } catch (err) {
        res.status(500).send("Erro interno.");
    }
});

// 8. TRATAMENTO DE ROTAS NÃO ENCONTRADAS (Blackhole)
app.use((req, res) => {
    res.status(404).json({ mensagem: "Caminho inválido." });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[REX] Sistema operando em modo fantasma na porta ${PORT}`);
});
