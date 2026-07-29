# ComAgente Middleware

Backend Serverless (Python) para a plataforma ComAgente — hospedado na Vercel.

## Estrutura do Projeto

```
comagente-middleware/
├── api/
│   └── mascarar.py      # Middleware de Mascaramento LGPD
├── vercel.json          # Configuração da Vercel
├── requirements.txt     # Dependências Python (vazio — usa somente stdlib)
└── README.md
```

## Rotas disponíveis

| Método | Endpoint        | Descrição                              |
|--------|-----------------|----------------------------------------|
| POST   | `/api/mascarar` | Mascara PII no texto recebido do n8n   |
| GET    | `/api/mascarar` | Health-check do serviço                |

## Payload de Entrada (POST)

```json
{ "mensagem": "Meu CPF é 123.456.789-09 e meu telefone é (11) 99999-8888" }
```

## Payload de Saída

```json
{ "mensagem_segura": "Meu CPF é [CPF_OCULTO] e meu telefone é [TELEFONE_OCULTO]" }
```

## Deploy

```bash
# Instale a Vercel CLI (se necessário)
npm i -g vercel

# Deploy de produção
vercel --prod
```
