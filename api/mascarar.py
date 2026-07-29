"""
ComAgente — Middleware de Mascaramento LGPD
============================================
Rota  : POST /api/mascarar
Entrada: {"mensagem": "texto cru do cliente"}
Saída  : {"mensagem_segura": "texto com PII substituído por tokens"}

Autenticação:
  Todas as rotas exigem o header:  Authorization: Bearer <MAJANI_API_SECRET>
  Ausência ou token inválido → HTTP 401 (a execução é abortada antes
  de qualquer leitura de payload).

Dados protegidos:
  - CPF (com ou sem pontuação)
  - Telefones brasileiros (com/sem DDD, com/sem +55)

Runtime: Python 3.12 (Vercel Serverless — BaseHTTPRequestHandler)
Sem dependências externas → cold start mínimo, resposta < 200ms.
"""

from __future__ import annotations

import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler

# ─── Constantes ───────────────────────────────────────────────────────────────

_MAX_BODY_BYTES = 65_536  # 64 KB — proteção contra payloads abusivos

# Token esperado lido UMA vez no cold start (nunca logado, nunca exposto).
# Configure em: Vercel Dashboard → Project → Settings → Environment Variables
# Variável : MAJANI_API_SECRET
# Valor    : string aleatória de alta entropia (mínimo 32 caracteres)
_API_SECRET: str = os.environ.get('MAJANI_API_SECRET', '')

# ─── Autenticação ─────────────────────────────────────────────────────────────


def _token_valido(authorization_header: str | None) -> bool:
    """
    Valida o Bearer Token recebido no header Authorization.

    Usa `hmac.compare_digest` para comparação em tempo constante,
    eliminando vulnerabilidades de timing attack (onde um atacante
    poderia inferir caracteres corretos medindo o tempo de resposta).

    Regras de rejeição (retorna False):
      - Header ausente ou None
      - Header mal-formado (não começa com 'Bearer ')
      - Token não bate com MAJANI_API_SECRET
      - MAJANI_API_SECRET não foi configurada no ambiente

    Args:
        authorization_header: Valor bruto do header 'Authorization'.

    Returns:
        True apenas se o token for válido.
    """
    if not _API_SECRET:
        # Variável de ambiente não configurada → falha fechada (fail-closed)
        return False

    if not authorization_header or not authorization_header.startswith('Bearer '):
        return False

    token_recebido = authorization_header[len('Bearer '):]

    # compare_digest exige bytes ou str puro — garante comparação segura
    return hmac.compare_digest(token_recebido, _API_SECRET)

# ─── Padrões de Regex (compilados uma única vez no módulo) ────────────────────

# CPF — aceita os dois formatos:
#   Formatado  : 123.456.789-09
#   Sem máscara: 12345678909  (11 dígitos contíguos)
# O \b garante que não capturamos parciais de números maiores.
_RE_CPF = re.compile(
    r'\b'
    r'\d{3}[.\-]?\d{3}[.\-]?\d{3}[.\-]?\d{2}'
    r'\b'
)

# Telefone Brasileiro — cobre os formatos mais comuns:
#   +55 (11) 99999-9999
#   +55 11 99999-9999
#   (11) 99999-9999
#   (11) 9999-9999
#   11 99999-9999
#   99999-9999
#   999999999  (9 dígitos sem separadores, com DDD embutido é 11)
# Nota: o padrão é aplicado APÓS o CPF para evitar colisão em sequências de 11 dígitos.
_RE_TELEFONE = re.compile(
    r'(?:\+55[\s\-]?)?'           # prefixo +55  (opcional)
    r'(?:\(?\d{2}\)?[\s\-]?)?'   # DDD 2 dígitos (opcional, c/ ou s/ parênteses)
    r'\d{4,5}'                    # 4 ou 5 dígitos (prefixo do número)
    r'[\s\-]?'                    # separador opcional  (espaço ou hífen)
    r'\d{4}'                      # 4 dígitos finais
    r'\b'
)

# ─── Token de substituição ────────────────────────────────────────────────────

_TOKEN_CPF = '[CPF_OCULTO]'
_TOKEN_TEL = '[TELEFONE_OCULTO]'

# ─── Funções de Mascaramento ──────────────────────────────────────────────────


def _mascarar_pii(texto: str) -> str:
    """
    Aplica mascaramento sequencial de PII ao texto recebido.

    A ordem importa:
      1. CPF primeiro  → evita que 11 dígitos de um CPF sem máscara
         sejam parcialmente capturados pelo padrão de telefone.
      2. Telefone em seguida.

    Args:
        texto: String bruta recebida do cliente via n8n.

    Returns:
        String com todos os tokens PII substituídos.
    """
    texto = _RE_CPF.sub(_TOKEN_CPF, texto)
    texto = _RE_TELEFONE.sub(_TOKEN_TEL, texto)
    return texto


# ─── Handler Vercel (BaseHTTPRequestHandler) ──────────────────────────────────


class handler(BaseHTTPRequestHandler):
    """
    Handler nativo da Vercel para Python Serverless.

    A classe deve se chamar exatamente 'handler' para que o runtime
    da Vercel a identifique automaticamente.
    """

    # ── Rota Principal ────────────────────────────────────────────────────────

    def do_POST(self) -> None:  # noqa: N802
        """
        Recebe o payload do n8n, mascara os dados sensíveis e devolve
        o texto limpo pronto para ser enviado à API do Claude.

        A autenticação via Bearer Token é a PRIMEIRA verificação.
        Qualquer falha aqui aborta a execução antes de ler o body.
        """
        # ── 1. Autenticação — barreira de entrada ─────────────────────────────
        if not _token_valido(self.headers.get('Authorization')):
            self._send_error(401, 'Não autorizado. Header Authorization ausente ou inválido.')
            return

        # ── 2. Processamento do payload ───────────────────────────────────────
        try:
            content_length = int(self.headers.get('Content-Length', 0))

            # Proteção: corpo vazio
            if content_length == 0:
                self._send_error(400, 'Payload vazio. Envie {"mensagem": "..."}.')
                return

            # Proteção: payload muito grande
            if content_length > _MAX_BODY_BYTES:
                self._send_error(413, f'Payload excede o limite de {_MAX_BODY_BYTES} bytes.')
                return

            raw_body = self.rfile.read(content_length)
            payload: dict = json.loads(raw_body)

            mensagem = payload.get('mensagem')

            # Validação do campo obrigatório
            if mensagem is None:
                self._send_error(400, "Campo 'mensagem' ausente no payload.")
                return

            if not isinstance(mensagem, str):
                self._send_error(400, "Campo 'mensagem' deve ser do tipo string.")
                return

            mensagem_segura = _mascarar_pii(mensagem)

            self._send_json(200, {'mensagem_segura': mensagem_segura})

        except json.JSONDecodeError:
            self._send_error(400, 'Corpo da requisição não é um JSON válido.')
        except Exception:
            # Nunca exponha detalhes de exceção em produção (vazamento de info)
            self._send_error(500, 'Erro interno no servidor. Contate o suporte.')

    # ── Health-check (GET) ────────────────────────────────────────────────────

    def do_GET(self) -> None:  # noqa: N802
        """Endpoint de saúde — útil para monitoramento e CI/CD."""
        self._send_json(200, {
            'status': 'online',
            'servico': 'ComAgente LGPD Masking Middleware',
            'versao': '1.0.0',
        })

    # ── Helpers privados ──────────────────────────────────────────────────────

    def _send_json(self, status_code: int, data: dict) -> None:
        """Serializa e envia uma resposta JSON com os headers corretos."""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        # Previne caching de respostas que contêm dados sensíveis
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status_code: int, message: str) -> None:
        """Atalho para respostas de erro padronizadas."""
        self._send_json(status_code, {'erro': message})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        """
        Suprime o log padrão do BaseHTTPRequestHandler.

        Motivo duplo:
          1. Performance: evita I/O de disco desnecessário no cold start.
          2. Privacidade: impede que IPs e paths sejam logados em texto puro.
        """
