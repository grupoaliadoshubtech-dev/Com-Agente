"""
ComAgente — API Gateway (Entrypoint único)
==========================================
Todas as rotas passam por este handler. O roteamento é feito
internamente via self.path, sem nenhum framework externo.

Rotas disponíveis:
  POST /api/mascarar  → Mascaramento LGPD (CPF e telefone)
  POST /api/clientes  → Buscar ou criar cliente no Supabase
  GET  /              → Health-check

Variáveis de ambiente (Vercel Dashboard → Environment Variables):
  MAJANI_API_SECRET  → Bearer Token compartilhado com o n8n
  SUPABASE_URL       → https://wuzqqprhepbsmbmnenys.supabase.co
  SUPABASE_KEY       → service_role key do Supabase

Runtime: Python 3.12 — zero dependências externas.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO — lida uma única vez no cold start
# ═══════════════════════════════════════════════════════════════════════════════

_API_SECRET:   str = os.environ.get('MAJANI_API_SECRET', '')
_SUPABASE_URL: str = os.environ.get('SUPABASE_URL', '').rstrip('/')
_SUPABASE_KEY: str = os.environ.get('SUPABASE_KEY', '')

_MAX_BODY_BYTES = 65_536  # 64 KB — proteção contra payloads abusivos
_TIMEOUT_S      = 5       # timeout nas chamadas ao Supabase

# ═══════════════════════════════════════════════════════════════════════════════
# AUTENTICAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════


def _token_valido(authorization_header: str | None) -> bool:
    """
    Valida o Bearer Token via hmac.compare_digest (tempo constante).
    Fail-closed: rejeita tudo se MAJANI_API_SECRET não estiver configurada.
    """
    if not _API_SECRET:
        return False
    if not authorization_header or not authorization_header.startswith('Bearer '):
        return False
    return hmac.compare_digest(authorization_header[len('Bearer '):], _API_SECRET)


# ═══════════════════════════════════════════════════════════════════════════════
# MÓDULO: MASCARAMENTO LGPD
# ═══════════════════════════════════════════════════════════════════════════════

# Padrões compilados uma vez — reutilizados em todas as invocações quentes
_RE_CPF = re.compile(
    r'\b\d{3}[.\-]?\d{3}[.\-]?\d{3}[.\-]?\d{2}\b'
)
_RE_TELEFONE = re.compile(
    r'(?:\+55[\s\-]?)?'          # +55 opcional
    r'(?:\(?\d{2}\)?[\s\-]?)?'  # DDD opcional
    r'\d{4,5}[\s\-]?\d{4}\b'    # número com 8 ou 9 dígitos
)


def _mascarar_pii(texto: str) -> str:
    """CPF primeiro (evita colisão com padrão de telefone), telefone depois."""
    texto = _RE_CPF.sub('[CPF_OCULTO]', texto)
    texto = _RE_TELEFONE.sub('[TELEFONE_OCULTO]', texto)
    return texto


# ═══════════════════════════════════════════════════════════════════════════════
# MÓDULO: SUPABASE (clientes)
# ═══════════════════════════════════════════════════════════════════════════════


def _sb_headers(prefer_representation: bool = False) -> dict:
    """Headers padrão para a API REST do Supabase."""
    h = {
        'apikey':        _SUPABASE_KEY,
        'Authorization': f'Bearer {_SUPABASE_KEY}',
        'Content-Type':  'application/json',
    }
    if prefer_representation:
        h['Prefer'] = 'return=representation'
    return h


def _buscar_cliente(telefone: str, empresa_id: str) -> dict | None:
    """
    Consulta clientes filtrando por telefone + empresa_id.
    O filtro duplo garante isolamento multi-tenant.
    """
    params = urllib.parse.urlencode({
        'telefone':   f'eq.{telefone}',
        'empresa_id': f'eq.{empresa_id}',
        'select':     '*',
        'limit':      '1',
    })
    req = urllib.request.Request(
        f'{_SUPABASE_URL}/rest/v1/clientes?{params}',
        headers=_sb_headers(),
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
        data: list = json.loads(resp.read())
        return data[0] if data else None


def _criar_cliente(telefone: str, empresa_id: str) -> dict:
    """Insere novo cliente com status 'novo'. Retorna o registro criado."""
    body = json.dumps({
        'telefone':   telefone,
        'empresa_id': empresa_id,
        'nome':       'Novo Cliente',
        'status':     'novo',
    }).encode('utf-8')
    req = urllib.request.Request(
        f'{_SUPABASE_URL}/rest/v1/clientes',
        data=body,
        headers=_sb_headers(prefer_representation=True),
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
        return json.loads(resp.read())[0]


# ═══════════════════════════════════════════════════════════════════════════════
# HANDLER PRINCIPAL (entrypoint único da Vercel)
# ═══════════════════════════════════════════════════════════════════════════════


class handler(BaseHTTPRequestHandler):
    """
    Entrypoint único da Vercel.
    Autentica toda requisição e delega para o handler de rota correto.
    """

    # ── Dispatcher POST ───────────────────────────────────────────────────────

    def do_POST(self) -> None:  # noqa: N802
        """Autentica e roteia para o módulo correto com base no path."""

        # 1. Autenticação — barreira universal antes de qualquer processamento
        if not _token_valido(self.headers.get('Authorization')):
            self._send_error(401, 'Não autorizado. Header Authorization ausente ou inválido.')
            return

        # 2. Roteamento por path
        path = self.path.split('?')[0].rstrip('/')

        if path in ('/api/mascarar', '/mascarar'):
            self._handle_mascarar()
        elif path in ('/api/clientes', '/clientes'):
            self._handle_clientes()
        else:
            self._send_error(404, f"Rota não encontrada: '{path}'. Consulte GET / para ver as rotas disponíveis.")

    # ── Health-check GET ──────────────────────────────────────────────────────

    def do_GET(self) -> None:  # noqa: N802
        """Health-check — lista as rotas disponíveis."""
        self._send_json(200, {
            'status':  'online',
            'servico': 'ComAgente Middleware',
            'versao':  '1.1.0',
            'rotas': [
                'POST /api/mascarar  → mascaramento LGPD (CPF e telefone)',
                'POST /api/clientes  → buscar ou criar cliente no Supabase',
            ],
        })

    # ── Handler: /api/mascarar ────────────────────────────────────────────────

    def _handle_mascarar(self) -> None:
        """
        Recebe {"mensagem": "..."} e devolve {"mensagem_segura": "..."}.
        CPFs e telefones são substituídos por tokens antes de ir ao Claude.
        """
        try:
            payload = self._ler_payload()
            if payload is None:
                return  # erro já enviado por _ler_payload

            mensagem = payload.get('mensagem')

            if mensagem is None:
                self._send_error(400, "Campo 'mensagem' ausente no payload.")
                return
            if not isinstance(mensagem, str):
                self._send_error(400, "Campo 'mensagem' deve ser do tipo string.")
                return

            self._send_json(200, {'mensagem_segura': _mascarar_pii(mensagem)})

        except json.JSONDecodeError:
            self._send_error(400, 'JSON inválido no corpo da requisição.')
        except Exception:
            self._send_error(500, 'Erro interno no servidor.')

    # ── Handler: /api/clientes ────────────────────────────────────────────────

    def _handle_clientes(self) -> None:
        """
        Recebe {"telefone": "...", "empresa_id": "..."}.
        Busca o cliente no Supabase; cria se não existir.
        Devolve {"cliente": {...}, "criado": bool}.
        """
        try:
            payload = self._ler_payload()
            if payload is None:
                return

            telefone   = str(payload.get('telefone',   '')).strip()
            empresa_id = str(payload.get('empresa_id', '')).strip()

            if not telefone:
                self._send_error(400, "Campo 'telefone' é obrigatório.")
                return
            if not empresa_id:
                self._send_error(400, "Campo 'empresa_id' é obrigatório.")
                return

            cliente = _buscar_cliente(telefone, empresa_id)
            criado  = False

            if cliente is None:
                cliente = _criar_cliente(telefone, empresa_id)
                criado  = True

            self._send_json(200, {'cliente': cliente, 'criado': criado})

        except urllib.error.HTTPError as exc:
            erro = exc.read().decode('utf-8', errors='replace')
            self._send_error(502, f'Erro na comunicação com o banco de dados: {erro}')
        except json.JSONDecodeError:
            self._send_error(400, 'JSON inválido no corpo da requisição.')
        except Exception:
            self._send_error(500, 'Erro interno no servidor.')

    # ── Helpers privados ──────────────────────────────────────────────────────

    def _ler_payload(self) -> dict | None:
        """
        Lê e valida o corpo da requisição.
        Retorna o dict parseado, ou None (já enviou o erro ao cliente).
        """
        content_length = int(self.headers.get('Content-Length', 0))

        if content_length == 0:
            self._send_error(400, 'Payload vazio.')
            return None

        if content_length > _MAX_BODY_BYTES:
            self._send_error(413, f'Payload excede o limite de {_MAX_BODY_BYTES} bytes.')
            return None

        return json.loads(self.rfile.read(content_length))

    def _send_json(self, status_code: int, data: dict) -> None:
        """Serializa e envia resposta JSON com headers corretos."""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status_code: int, message: str) -> None:
        """Atalho para respostas de erro padronizadas."""
        self._send_json(status_code, {'erro': message})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        """Suprime logs — performance + privacidade (IPs não logados)."""
