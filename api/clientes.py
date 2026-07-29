"""
ComAgente — Rota de Clientes
==============================
Rota  : POST /api/clientes
Função: Busca um cliente pelo telefone e empresa_id.
        Se não existir, cria automaticamente (upsert).

Entrada:
  {
    "telefone":   "+5511999998888",
    "empresa_id": "uuid-da-empresa"
  }

Saída (cliente encontrado):
  {
    "cliente": { "id": "...", "nome": "...", "status": "ativo", ... },
    "criado": false
  }

Saída (cliente novo, criado agora):
  {
    "cliente": { "id": "...", "nome": "Novo Cliente", "status": "novo", ... },
    "criado": true
  }

Variáveis de ambiente necessárias (Vercel Dashboard → Environment Variables):
  MAJANI_API_SECRET  → token de autenticação (mesmo do /api/mascarar)
  SUPABASE_URL       → https://wuzqqprhepbsmbmnenys.supabase.co
  SUPABASE_KEY       → service_role key (recomendado) ou publishable key

Runtime: Python 3.12 — zero dependências externas.
"""

from __future__ import annotations

import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

# ─── Configuração (lida uma vez no cold start) ────────────────────────────────

_API_SECRET:    str = os.environ.get('MAJANI_API_SECRET', '')
_SUPABASE_URL:  str = os.environ.get('SUPABASE_URL', '').rstrip('/')
_SUPABASE_KEY:  str = os.environ.get('SUPABASE_KEY', '')

_MAX_BODY_BYTES = 65_536  # 64 KB
_TIMEOUT_S      = 5       # timeout nas chamadas ao Supabase

# ─── Autenticação ─────────────────────────────────────────────────────────────


def _token_valido(authorization_header: str | None) -> bool:
    """
    Valida o Bearer Token via comparação em tempo constante.
    Idêntico ao padrão de /api/mascarar — fail-closed se env var ausente.
    """
    if not _API_SECRET:
        return False
    if not authorization_header or not authorization_header.startswith('Bearer '):
        return False
    return hmac.compare_digest(authorization_header[len('Bearer '):], _API_SECRET)


# ─── Helpers do Supabase REST API ─────────────────────────────────────────────


def _headers_supabase(prefer_representation: bool = False) -> dict:
    """
    Monta os headers padrão para chamadas à API REST do Supabase.

    'Prefer: return=representation' faz o Supabase devolver o registro
    criado/atualizado no corpo da resposta (necessário no INSERT).
    """
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
    Consulta a tabela 'clientes' filtrando por telefone + empresa_id.

    O filtro duplo (telefone + empresa_id) é o que garante o isolamento
    multi-tenant: um mesmo telefone pode ser cliente de empresas diferentes.

    Returns:
        dict com os dados do cliente, ou None se não encontrado.
    """
    params = urllib.parse.urlencode({
        'telefone':   f'eq.{telefone}',
        'empresa_id': f'eq.{empresa_id}',
        'select':     '*',
        'limit':      '1',
    })
    url = f'{_SUPABASE_URL}/rest/v1/clientes?{params}'
    req = urllib.request.Request(url, headers=_headers_supabase())

    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
        data: list = json.loads(resp.read())
        return data[0] if data else None


def _criar_cliente(telefone: str, empresa_id: str) -> dict:
    """
    Insere um novo cliente na tabela 'clientes' com status 'novo'.

    O campo 'nome' começa como 'Novo Cliente' e pode ser atualizado
    posteriormente quando o cliente informar o nome na conversa.

    Returns:
        dict com os dados do cliente recém-criado (incluindo o id gerado).
    """
    url  = f'{_SUPABASE_URL}/rest/v1/clientes'
    body = json.dumps({
        'telefone':   telefone,
        'empresa_id': empresa_id,
        'nome':       'Novo Cliente',
        'status':     'novo',
    }).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=body,
        headers=_headers_supabase(prefer_representation=True),
        method='POST',
    )

    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
        data: list = json.loads(resp.read())
        return data[0]


# ─── Handler Vercel ───────────────────────────────────────────────────────────


class handler(BaseHTTPRequestHandler):
    """Handler nativo da Vercel — nome 'handler' é obrigatório."""

    def do_POST(self) -> None:  # noqa: N802
        """
        Busca ou cria um cliente no Supabase.

        Fluxo:
          1. Autentica o Bearer Token
          2. Valida o payload (telefone + empresa_id)
          3. Busca o cliente no Supabase
          4. Se não existir → cria
          5. Devolve os dados + flag 'criado' para o n8n
        """
        # ── 1. Autenticação ───────────────────────────────────────────────────
        if not _token_valido(self.headers.get('Authorization')):
            self._send_error(401, 'Não autorizado. Header Authorization ausente ou inválido.')
            return

        # ── 2. Validação do payload ───────────────────────────────────────────
        try:
            content_length = int(self.headers.get('Content-Length', 0))

            if content_length == 0:
                self._send_error(400, 'Payload vazio. Envie {"telefone": "...", "empresa_id": "..."}.')
                return

            if content_length > _MAX_BODY_BYTES:
                self._send_error(413, f'Payload excede o limite de {_MAX_BODY_BYTES} bytes.')
                return

            payload: dict = json.loads(self.rfile.read(content_length))

            telefone   = str(payload.get('telefone',   '')).strip()
            empresa_id = str(payload.get('empresa_id', '')).strip()

            if not telefone:
                self._send_error(400, "Campo 'telefone' é obrigatório.")
                return

            if not empresa_id:
                self._send_error(400, "Campo 'empresa_id' é obrigatório.")
                return

        except json.JSONDecodeError:
            self._send_error(400, 'Corpo da requisição não é um JSON válido.')
            return

        # ── 3 e 4. Busca → cria se necessário ────────────────────────────────
        try:
            cliente = _buscar_cliente(telefone, empresa_id)
            criado  = False

            if cliente is None:
                cliente = _criar_cliente(telefone, empresa_id)
                criado  = True

        except urllib.error.HTTPError as exc:
            erro_supabase = exc.read().decode('utf-8', errors='replace')
            self._send_error(502, f'Erro na comunicação com o banco de dados: {erro_supabase}')
            return
        except Exception:
            self._send_error(500, 'Erro interno no servidor. Contate o suporte.')
            return

        # ── 5. Resposta para o n8n ────────────────────────────────────────────
        self._send_json(200, {
            'cliente': cliente,
            'criado':  criado,
        })

    def _send_json(self, status_code: int, data: dict) -> None:
        """Serializa e envia resposta JSON."""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status_code: int, message: str) -> None:
        """Atalho para respostas de erro."""
        self._send_json(status_code, {'erro': message})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        """Suprime logs — performance + privacidade."""
