# ============================================================
#  MrDesk Suporte - Backend
#  Sysrs Tecnologia da Informacao
# ============================================================

from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
import bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from datetime import datetime, timedelta
import os
import sys
import time
import threading
import hmac
import re
import smtplib
from email.message import EmailMessage
import config

app = Flask(__name__)
serializer = URLSafeTimedSerializer(config.APP_SECRET_KEY)

TOKEN_MAX_AGE = 60 * 60 * 12  # 12 horas

# ------------------------------------------------------------
# ATUALIZACAO AUTOMATICA DO CLIENTE MRDESK
# ------------------------------------------------------------
# O client MrDesk (patch em rdgen/generator-windows.yml) manda um POST pra
# /api/version/latest perguntando se ha versao nova.
#
# Os exes de atualizacao ficam AQUI MESMO na VM, em UPDATES_DIR, e o Nginx
# serve os dois direto da pasta (location /updates/):
#   https://mrdesk.sysrs.com.br/updates/mrdesk.exe     (clientes)
#   https://mrdesk.sysrs.com.br/updates/mrdeskpro.exe  (tecnico)
# Cada build ja tem gravado o link do seu proprio exe (campo downloadLink
# do rdgen).
#
# Publicar versao nova = subir os DOIS exes nessa pasta (WinSCP). So isso.
# Nao existe mais version.txt: a versao anunciada e lida de dentro dos
# proprios exes (ProductVersion - a mesma que aparece em Propriedades >
# Detalhes no Windows). Assim a versao anunciada e sempre a do exe que esta
# sendo servido, e o client nunca entra em loop de reinstalacao.
#
# So anunciamos versao se os DOIS exes existirem e tiverem a MESMA versao.
# Se faltar um, ou se estiverem diferentes (ex.: subiu so um), responde
# "sem update" - ninguem atualiza ate os dois baterem.
#
# A leitura do exe so acontece quando o arquivo muda (data/tamanho); nas
# demais consultas a versao sai do cache em memoria.
#
# O client compara a versao anunciada com a dele. Se a daqui for MAIOR, ele
# atualiza (MrDesk: aviso na tela + silencioso; MrDeskPro: so aviso).
UPDATES_DIR = "/opt/mrdesk-suporte/updates"
UPDATE_EXES = ("mrdesk.exe", "mrdeskpro.exe")
UPDATE_CHECK_HOST = "https://mrdesk.sysrs.com.br"

# caminho -> (mtime, tamanho, versao)
_exe_version_cache = {}


def _ler_versao_exe(caminho):
    """Le a ProductVersion (ou FileVersion) gravada no exe. "" se nao achar."""
    import pefile
    pe = pefile.PE(caminho, fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        textos = {}
        for info in getattr(pe, "FileInfo", None) or []:
            for bloco in info:
                for tabela in getattr(bloco, "StringTable", []) or []:
                    for chave, valor in tabela.entries.items():
                        textos[chave.decode(errors="ignore")] = valor.decode(errors="ignore")
        versao = (textos.get("ProductVersion") or textos.get("FileVersion") or "").strip()
        if not versao and getattr(pe, "VS_FIXEDFILEINFO", None):
            f = pe.VS_FIXEDFILEINFO[0]
            versao = "%d.%d.%d" % (f.ProductVersionMS >> 16, f.ProductVersionMS & 0xFFFF,
                                   f.ProductVersionLS >> 16)
        return versao
    finally:
        pe.close()


def _versao_do_exe(nome):
    caminho = os.path.join(UPDATES_DIR, nome)
    try:
        st = os.stat(caminho)
    except FileNotFoundError:
        return ""
    em_cache = _exe_version_cache.get(caminho)
    if em_cache and em_cache[0] == st.st_mtime and em_cache[1] == st.st_size:
        return em_cache[2]
    try:
        versao = _ler_versao_exe(caminho)
    except Exception as e:
        app.logger.error("Falha ao ler versao de %s: %s", caminho, e)
        versao = ""
    _exe_version_cache[caminho] = (st.st_mtime, st.st_size, versao)
    return versao


def get_current_update_version():
    versoes = [_versao_do_exe(nome) for nome in UPDATE_EXES]
    if not all(versoes) or len(set(versoes)) != 1:
        # Falta um exe, algum sem versao legivel, ou versoes diferentes:
        # nao anuncia nada.
        return ""
    return versoes[0]


@app.route("/api/version/latest", methods=["POST"])
def version_latest():
    # Corpo enviado pelo client (os, os_version, arch, device_id, typ) -
    # nao usamos os campos hoje, mas aceitamos qualquer coisa aqui.
    request.get_json(force=True, silent=True)

    version = get_current_update_version()
    if not version:
        # Responde um formato valido, mas que nunca aciona atualizacao.
        return jsonify({"url": ""})

    return jsonify({"url": f"{UPDATE_CHECK_HOST}/tag/{version}"})


@app.route("/api/version/status", methods=["GET"])
def version_status():
    # Conferencia rapida pro tecnico: versao lida de cada exe e o que esta
    # sendo anunciado. So leitura, sem dados sensiveis.
    return jsonify({
        "exes": {nome: (_versao_do_exe(nome) or None) for nome in UPDATE_EXES},
        "anunciada": get_current_update_version() or None,
    })


# ------------------------------------------------------------
# SESSAO DO PAINEL (item 41)
# ------------------------------------------------------------
# O token guarda so o numero do usuario; tudo o mais (nome, tipo, se continua
# ativo) e lido do banco a cada pedido. Assim a sessao cai na hora quando:
#   - o usuario e desativado;
#   - o admin da empresa dele (master) e desativado;
#   - a senha e trocada (usuarios.senha_alterada posterior a criacao do token).
# So admin entra no painel (superadmin e admin de empresa); tecnico usa o
# MrDeskPro.
# Conta da Sysrs (usuario admin da empresa Sysrs): so ela e o superadmin veem
# os graficos do servidor; so ela tem Licenca MR1, Versao MR1 e "Liberar nova
# maquina".
CONTA_SYSRS = getattr(config, "CONTA_SYSRS", 2)


def gerar_token(usuario_id):
    return serializer.dumps({"u": usuario_id})


_SQL_SESSAO = (
    "SELECT u.usuario, u.nome, u.email, u.admin, u.master, u.ativo, "
    "COALESCE(m.ativo, 'S') AS master_ativo, "
    "(u.senha_alterada IS NULL OR u.senha_alterada <= to_timestamp(%s)::timestamp) AS sessao_ok "
    "FROM usuarios u LEFT JOIN usuarios m ON m.usuario = u.master WHERE u.usuario = %s"
)


def _usuario_da_sessao(cur, usuario_id, emitido):
    # Devolve a linha do usuario se a sessao criada em "emitido" (segundos
    # desde 1970) continua valendo; senao None. Cursor comum (tupla).
    cur.execute(_SQL_SESSAO, (emitido, usuario_id))
    r = cur.fetchone()
    if not r:
        return None
    usuario, nome, email, admin, master, ativo, master_ativo, sessao_ok = r
    if ativo != "S" or master_ativo != "S" or not sessao_ok:
        return None
    return {"usuario": usuario, "nome": nome, "email": email, "admin": admin, "master": master}


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"success": False, "error": "Login necessario"}), 401
        try:
            data, emitido = serializer.loads(token, max_age=TOKEN_MAX_AGE, return_timestamp=True)
            usuario_id = int(data["u"])
        except SignatureExpired:
            return jsonify({"success": False, "error": "Sessao expirada, faca login novamente"}), 401
        except (BadSignature, KeyError, TypeError, ValueError):
            # inclui os tokens antigos (anteriores ao item 41), que nao tem "u"
            return jsonify({"success": False, "error": "Sessao expirada, faca login novamente"}), 401

        conn = get_db()
        cur = conn.cursor()
        user = _usuario_da_sessao(cur, usuario_id, int(emitido.timestamp()))
        cur.close()
        conn.close()
        if not user or user["admin"] != "S":
            return jsonify({"success": False, "error": "Sessao expirada, faca login novamente"}), 401

        request.usuario_id = user["usuario"]
        request.usuario_logado = user["nome"]
        request.usuario_email = user["email"]
        request.usuario_admin = True
        request.usuario_super = user["master"] is None
        request.usuario_sysrs = user["usuario"] == CONTA_SYSRS
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    # Todo usuario do painel e admin (superadmin ou admin de empresa).
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(request, "usuario_admin", False):
            return jsonify({"success": False, "error": "Acesso restrito a administradores"}), 403
        return f(*args, **kwargs)
    return decorated


def require_super(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(request, "usuario_super", False):
            return jsonify({"success": False, "error": "Acesso restrito ao superadministrador"}), 403
        return f(*args, **kwargs)
    return decorated


def require_sysrs(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(request, "usuario_sysrs", False):
            return jsonify({"success": False, "error": "Recurso nao disponivel para esta conta"}), 403
        return f(*args, **kwargs)
    return decorated


def require_sysrs_ou_super(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not (getattr(request, "usuario_sysrs", False) or getattr(request, "usuario_super", False)):
            return jsonify({"success": False, "error": "Recurso nao disponivel para esta conta"}), 403
        return f(*args, **kwargs)
    return decorated


def require_admin_empresa(f):
    # So o admin de empresa (o superadmin nao tem conta): catalogos,
    # dispositivos, auditoria e tecnicos autorizados.
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(request, "usuario_super", True):
            return jsonify({"success": False, "error": "Acesso restrito ao administrador da empresa"}), 403
        return f(*args, **kwargs)
    return decorated


# ------------------------------------------------------------
# TRAFEGO DE SAIDA DA VM (limite do plano Always Free da Oracle)
# ------------------------------------------------------------
# A Oracle da 10 TB/mes de saida de graca (conta toda). O vnstat, instalado
# na VM, conta o trafego por interface; aqui somamos o "tx" (saida) do mes
# atual de todas as interfaces, menos a loopback. Resultado guardado em
# memoria por 5 min pra nao rodar o vnstat a cada acesso da tela.
LIMITE_TRAFEGO_BYTES = 10 * 10**12  # 10 TB
_trafego_cache = {"quando": 0, "dados": None}


def _trafego_mes_atual():
    import json, subprocess, time
    agora = time.time()
    if _trafego_cache["dados"] is not None and agora - _trafego_cache["quando"] < 300:
        return _trafego_cache["dados"]

    saida = subprocess.run(["vnstat", "--json", "m"], capture_output=True, text=True, timeout=10)
    dados = json.loads(saida.stdout)
    # vnstat 2.x: "month" em bytes; vnstat 1.x: "months" em KiB
    fator = 1 if str(dados.get("jsonversion", "1")) == "2" else 1024
    hoje = datetime.now()
    tx = 0
    for iface in dados.get("interfaces", []):
        nome = iface.get("name") or iface.get("id") or ""
        if nome == "lo":
            continue
        trafego = iface.get("traffic", {})
        for mes in trafego.get("month") or trafego.get("months") or []:
            d = mes.get("date", {})
            if d.get("year") == hoje.year and d.get("month") == hoje.month:
                tx += int(mes.get("tx", 0)) * fator

    resultado = {
        "mes": hoje.strftime("%m/%Y"),
        "saida_bytes": tx,
        "limite_bytes": LIMITE_TRAFEGO_BYTES,
        "percentual": round(tx * 100 / LIMITE_TRAFEGO_BYTES, 3),
    }
    _trafego_cache["quando"] = agora
    _trafego_cache["dados"] = resultado
    return resultado


@app.route("/api/trafego", methods=["GET"])
@require_auth
@require_sysrs_ou_super
def trafego():
    try:
        return jsonify({"success": True, **_trafego_mes_atual()})
    except Exception as e:
        app.logger.error("Falha ao ler trafego do vnstat: %s", e)
        return jsonify({"success": False, "error": "Nao foi possivel ler o trafego (vnstat)"}), 500


# ------------------------------------------------------------
# ESPACO EM DISCO DA VM (disco principal "/", onde ficam sistema, banco
# PostgreSQL em /usr/local/pgsql/data, builds do rdgen, logs etc.)
# ------------------------------------------------------------
# Mesmo calculo do "df -h /": usado / (usado + disponivel).
@app.route("/api/disco", methods=["GET"])
@require_auth
@require_sysrs_ou_super
def disco():
    try:
        st = os.statvfs("/")
        total_bytes = st.f_blocks * st.f_frsize
        livre_bytes = st.f_bavail * st.f_frsize
        usado_bytes = (st.f_blocks - st.f_bfree) * st.f_frsize
        percentual = round(usado_bytes * 100 / (usado_bytes + livre_bytes), 1) if usado_bytes + livre_bytes else 0
        return jsonify({
            "success": True,
            "total_bytes": total_bytes,
            "usado_bytes": usado_bytes,
            "livre_bytes": livre_bytes,
            "percentual": percentual,
        })
    except Exception as e:
        app.logger.error("Falha ao ler espaco em disco: %s", e)
        return jsonify({"success": False, "error": "Nao foi possivel ler o espaco em disco"}), 500


# ------------------------------------------------------------
# MEMORIA DA VM (pizza no cabecalho, depois da do disco)
# ------------------------------------------------------------
# Le /proc/meminfo. "Usada" = MemTotal - MemAvailable (o mesmo que a coluna
# "used"/"available" do comando free: cache do sistema que pode ser liberado
# nao conta como usado).
@app.route("/api/memoria", methods=["GET"])
@require_auth
@require_sysrs_ou_super
def memoria():
    try:
        valores = {}
        with open("/proc/meminfo") as f:
            for linha in f:
                nome, _, resto = linha.partition(":")
                partes = resto.split()
                if partes:
                    valores[nome.strip()] = int(partes[0]) * 1024  # kB -> bytes
        total_bytes = valores["MemTotal"]
        disponivel_bytes = valores.get("MemAvailable", valores.get("MemFree", 0))
        usado_bytes = total_bytes - disponivel_bytes
        percentual = round(usado_bytes * 100 / total_bytes, 1) if total_bytes else 0
        return jsonify({
            "success": True,
            "total_bytes": total_bytes,
            "usado_bytes": usado_bytes,
            "percentual": percentual,
        })
    except Exception as e:
        app.logger.error("Falha ao ler a memoria: %s", e)
        return jsonify({"success": False, "error": "Nao foi possivel ler a memoria"}), 500


def get_db():
    return psycopg2.connect(
        host=config.DB_HOST,
        dbname=config.DB_NAME,
        user=config.DB_USER,
        password=config.DB_PASSWORD
    )


# ------------------------------------------------------------
# USUARIOS, LOGIN E SENHA (item 41)
# ------------------------------------------------------------
# Tres tipos de usuario (regras garantidas tambem por triggers no banco):
#   superadmin       : master nulo, admin = 'S'. Um so. Cria e edita so os
#                      admins de empresa.
#   admin de empresa : admin = 'S', master = superadmin. Cria e edita so os
#                      tecnicos dele. Entra no painel e no MrDeskPro.
#   tecnico          : admin = 'N', master = admin da empresa. So MrDeskPro.
# "admin" e "master" NUNCA sao lidos do que a tela manda: saem do usuario
# logado (quem cria e o master; o superadmin cria admin, o admin cria tecnico).
# Login = e-mail. Ninguem define a senha de outro: o usuario recebe por e-mail
# um link (uso unico, 24 h) e cria a propria senha.
PAINEL_URL = getattr(config, "PAINEL_URL", "https://mrdesk.sysrs.com.br").rstrip("/")
serializer_link = URLSafeTimedSerializer(config.APP_SECRET_KEY, salt="link-senha")
VALIDADE_LINK_SENHA = 60 * 60 * 24  # 24 horas
TAMANHO_MINIMO_SENHA = 8
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MSG_LINK_INVALIDO = "Link inválido ou vencido. Peça um novo em \"Esqueci minha senha\"."

# Tentativas de login com senha errada, por e-mail + IP (em memoria, por
# worker): 5 erros em 15 minutos bloqueiam aquele e-mail naquele IP ate a
# janela passar. Vale pro painel e pro MrDeskPro juntos. (So pelo e-mail nao:
# qualquer um travaria o login de outra pessoa errando a senha de proposito.)
LIMITE_FALHAS_LOGIN = 5
JANELA_FALHAS_LOGIN = 15 * 60
_falhas_login = {}
# Pedidos de "Esqueci minha senha": por IP e por e-mail.
LIMITE_ESQUECI_POR_IP = 5          # a cada 15 minutos
INTERVALO_ESQUECI_POR_EMAIL = 5 * 60
_esqueci_por_ip = {}
_esqueci_por_email = {}
_limites_lock = threading.Lock()


def _ip():
    return request.headers.get("X-Real-IP") or request.remote_addr or None


def _normalizar_email(valor):
    return (valor or "").strip().lower()


def _chave_login(email):
    return f"{email}|{_ip() or '?'}"


def _login_bloqueado(email):
    email = _chave_login(email)
    agora = time.time()
    with _limites_lock:
        janela = [t for t in _falhas_login.get(email, []) if agora - t < JANELA_FALHAS_LOGIN]
        if janela:
            _falhas_login[email] = janela
        else:
            _falhas_login.pop(email, None)
        return len(janela) >= LIMITE_FALHAS_LOGIN


def _registrar_falha_login(email):
    email = _chave_login(email)
    agora = time.time()
    with _limites_lock:
        if len(_falhas_login) > 10000:  # nao deixa crescer sem fim
            for chave in [k for k, v in _falhas_login.items() if not v or agora - v[-1] >= JANELA_FALHAS_LOGIN]:
                del _falhas_login[chave]
        _falhas_login.setdefault(email, []).append(agora)


def _limpar_falhas_login(email):
    email = _chave_login(email)
    with _limites_lock:
        _falhas_login.pop(email, None)


def _erro_regra_senha(senha):
    if len(senha) < TAMANHO_MINIMO_SENHA:
        return f"A senha deve ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres."
    if len(senha.encode()) > 72:
        return "A senha deve ter no máximo 72 caracteres."
    if not re.search(r"[A-Za-z]", senha) or not re.search(r"[0-9]", senha):
        return "A senha deve ter pelo menos uma letra e um número."
    return None


def _senha_confere(senha, resumo):
    # resumo nulo = usuario aguardando definir a senha: nunca confere.
    if not resumo:
        return False
    try:
        return bcrypt.checkpw(senha.encode(), resumo.encode())
    except ValueError:
        return False


def _log_usuario(cur, usuario, acao, autor=None, detalhe=None, ip=None):
    cur.execute(
        "INSERT INTO log_usuarios (usuario, acao, autor, detalhe, ip) VALUES (%s, %s, %s, %s, %s)",
        (usuario, acao, autor, (detalhe or None) and detalhe[:200], ip)
    )


def _enviar_email(destino, assunto, texto):
    # Devolve (True, None) ou (False, motivo). Dados do envio no config.py.
    host = getattr(config, "SMTP_HOST", "")
    if not host:
        return False, "envio de e-mail não configurado no servidor"
    usuario = getattr(config, "SMTP_USUARIO", "")
    msg = EmailMessage()
    msg["Subject"] = assunto
    msg["From"] = getattr(config, "SMTP_REMETENTE", "") or usuario
    msg["To"] = destino
    msg.set_content(texto)
    try:
        porta = int(getattr(config, "SMTP_PORT", 587))
        seguranca = getattr(config, "SMTP_SEGURANCA", "starttls")
        if seguranca == "ssl":
            srv = smtplib.SMTP_SSL(host, porta, timeout=15)
        else:
            srv = smtplib.SMTP(host, porta, timeout=15)
        with srv:
            if seguranca == "starttls":
                srv.starttls()
            if usuario:
                srv.login(usuario, getattr(config, "SMTP_SENHA", ""))
            srv.send_message(msg)
        return True, None
    except Exception as e:
        print(f"falha ao enviar e-mail para {destino}: {e}", file=sys.stderr, flush=True)
        return False, "o servidor de e-mail recusou o envio"


def _enviar_link_senha(usuario_id, motivo, autor=None, ip=None):
    # Gera um link novo (o anterior deixa de valer), manda por e-mail e registra.
    # motivo: "convite" (usuario novo ou e-mail trocado) ou "redefinicao".
    # Devolve (True, None) ou (False, motivo da falha).
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT u.nome, u.email, u.admin, u.ativo, COALESCE(m.ativo, 'S') "
        "FROM usuarios u LEFT JOIN usuarios m ON m.usuario = u.master WHERE u.usuario = %s",
        (usuario_id,)
    )
    r = cur.fetchone()
    if not r or r[3] != "S" or r[4] != "S":
        cur.close()
        conn.close()
        return False, "usuário inativo"
    nome, email, admin = r[0], r[1], r[2]

    momento = int(time.time())
    cur.execute("UPDATE usuarios SET link_senha = to_timestamp(%s)::timestamp WHERE usuario = %s",
                (momento, usuario_id))
    conn.commit()
    link = f"{PAINEL_URL}/?senha={serializer_link.dumps({'u': usuario_id, 't': momento})}"

    if admin == "S":
        onde = f"Depois, você entra no painel ({PAINEL_URL}) e no MrDeskPro com este e-mail e a senha criada."
    else:
        onde = "Depois, você entra no MrDeskPro com este e-mail e a senha criada."
    if motivo == "convite":
        assunto = "MrDesk - crie a sua senha"
        abertura = "Foi criado um usuário para você no MrDesk. Para criar a sua senha, abra o link abaixo:"
    else:
        assunto = "MrDesk - redefinição de senha"
        abertura = "Recebemos um pedido para redefinir a sua senha do MrDesk. Para criar uma senha nova, abra o link abaixo:"
    texto = (
        f"Olá, {nome}.\n\n{abertura}\n\n{link}\n\n"
        "O link vale por 24 horas e só pode ser usado uma vez.\n"
        f"Seu login: {email}\n{onde}\n\n"
        "Se você não esperava este e-mail, ignore-o: nada muda enquanto o link não for usado.\n"
    )
    ok, erro = _enviar_email(email, assunto, texto)
    _log_usuario(cur, usuario_id, "L", autor,
                 motivo + ("" if ok else " (falha no envio do e-mail)"), ip)
    conn.commit()
    cur.close()
    conn.close()
    return ok, erro


def _avisar_senha_alterada(nome, email):
    # Em segundo plano: quem trocou a senha nao espera o servidor de e-mail.
    texto = (
        f"Olá, {nome}.\n\nA senha do seu usuário no MrDesk ({email}) acabou de ser alterada.\n\n"
        "Se foi você, não precisa fazer nada.\n"
        f"Se não foi você, redefina a senha agora em {PAINEL_URL} (\"Esqueci minha senha\") "
        "e avise o administrador.\n"
    )
    threading.Thread(target=_enviar_email, args=(email, "MrDesk - sua senha foi alterada", texto),
                     daemon=True).start()


def _usuario_do_link(cur, token):
    # Devolve (usuario, nome, email, admin, tinha_senha) se o link vale; senao None.
    try:
        dados = serializer_link.loads(token or "", max_age=VALIDADE_LINK_SENHA)
        usuario_id, momento = int(dados["u"]), int(dados["t"])
    except (SignatureExpired, BadSignature, KeyError, TypeError, ValueError):
        return None
    cur.execute(
        "SELECT u.usuario, u.nome, u.email, u.admin, u.senha IS NOT NULL "
        "FROM usuarios u LEFT JOIN usuarios m ON m.usuario = u.master "
        "WHERE u.usuario = %s AND u.link_senha = to_timestamp(%s)::timestamp "
        "AND u.ativo = 'S' AND COALESCE(m.ativo, 'S') = 'S'",
        (usuario_id, momento)
    )
    return cur.fetchone()


# ---- Login do painel ----
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    # Mesmo endereco do login do MrDeskPro (item 24): o RustDesk manda id/uuid.
    if data.get("uuid") and data.get("id"):
        return login_pro()
    email = _normalizar_email(data.get("username"))
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "E-mail e senha obrigatórios"}), 400
    if _excedeu_limite_login_pro(_ip() or "?") or _login_bloqueado(email):
        return jsonify({"success": False, "error": "Muitas tentativas. Aguarde alguns minutos e tente de novo."}), 429

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT u.usuario, u.nome, u.senha, u.admin, u.master FROM usuarios u "
        "LEFT JOIN usuarios m ON m.usuario = u.master "
        "WHERE u.email = %s AND u.ativo = 'S' AND COALESCE(m.ativo, 'S') = 'S'",
        (email,)
    )
    user = cur.fetchone()

    if not user or not _senha_confere(password, user["senha"]):
        cur.close()
        conn.close()
        _registrar_falha_login(email)
        return jsonify({"success": False, "error": "E-mail ou senha inválidos"}), 401

    _limpar_falhas_login(email)
    if user["admin"] != "S":
        cur.close()
        conn.close()
        return jsonify({"success": False,
                        "error": "O painel é só para administradores. Técnicos entram pelo MrDeskPro."}), 403

    cur.execute("UPDATE usuarios SET ultimo_login = NOW() WHERE usuario = %s", (user["usuario"],))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "success": True,
        "name": user["nome"],
        "admin": True,
        "super": user["master"] is None,
        "sysrs": user["usuario"] == CONTA_SYSRS,
        "token": gerar_token(user["usuario"])
    })


# ---- Alterar a propria senha (usuario logado no painel) ----
@app.route("/api/usuarios/senha", methods=["PUT"])
@require_auth
def alterar_propria_senha():
    data = request.get_json(force=True, silent=True) or {}
    senha_atual = data.get("senha_atual") or ""
    nova_senha = data.get("nova_senha") or ""

    if not senha_atual or not nova_senha:
        return jsonify({"success": False, "error": "Senha atual e nova senha são obrigatórias"}), 400
    erro = _erro_regra_senha(nova_senha)
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT senha FROM usuarios WHERE usuario = %s", (request.usuario_id,))
    row = cur.fetchone()
    if not row or not _senha_confere(senha_atual, row[0]):
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Senha atual incorreta"}), 401

    nova_senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        "UPDATE usuarios SET senha = %s, senha_alterada = date_trunc('second', NOW()), "
        "link_senha = NULL, alterado = NOW() WHERE usuario = %s",
        (nova_senha_hash, request.usuario_id)
    )
    _log_usuario(cur, request.usuario_id, "S", request.usuario_id, "alterada no painel", _ip())
    conn.commit()
    cur.close()
    conn.close()

    _avisar_senha_alterada(request.usuario_logado, request.usuario_email)
    # As outras sessoes cairam; esta continua com um token novo.
    return jsonify({"success": True, "token": gerar_token(request.usuario_id)})


# ---- Esqueci minha senha / definir senha pelo link (sem login) ----
def _processar_esqueci(email, ip):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT u.usuario FROM usuarios u LEFT JOIN usuarios m ON m.usuario = u.master "
        "WHERE u.email = %s AND u.ativo = 'S' AND COALESCE(m.ativo, 'S') = 'S'",
        (email,)
    )
    r = cur.fetchone()
    cur.close()
    conn.close()
    if r:
        _enviar_link_senha(r[0], "redefinicao", None, ip)


@app.route("/api/senha/esqueci", methods=["POST"])
def esqueci_senha():
    # Responde sempre a mesma coisa, exista o e-mail ou nao (nao revela quem
    # tem cadastro). A consulta e o envio rodam em segundo plano.
    data = request.get_json(force=True, silent=True) or {}
    email = _normalizar_email(data.get("email"))
    ip = _ip()
    agora = time.time()
    liberado = bool(email) and bool(_RE_EMAIL.match(email)) and len(email) <= 100
    with _limites_lock:
        janela = [t for t in _esqueci_por_ip.get(ip or "?", []) if agora - t < JANELA_FALHAS_LOGIN]
        janela.append(agora)
        _esqueci_por_ip[ip or "?"] = janela
        if len(janela) > LIMITE_ESQUECI_POR_IP:
            liberado = False
        if liberado and agora - _esqueci_por_email.get(email, 0) < INTERVALO_ESQUECI_POR_EMAIL:
            liberado = False
        if liberado:
            _esqueci_por_email[email] = agora
        for tabela in (_esqueci_por_ip, _esqueci_por_email):
            if len(tabela) > 10000:  # nao deixa crescer sem fim
                tabela.clear()
    if liberado:
        threading.Thread(target=_processar_esqueci, args=(email, ip), daemon=True).start()
    return jsonify({"success": True})


@app.route("/api/senha/link", methods=["GET"])
def conferir_link_senha():
    if _excedeu_limite_verificacao(_ip() or "?"):
        return jsonify({"success": False, "error": "Muitas tentativas. Aguarde um minuto."}), 429
    conn = get_db()
    cur = conn.cursor()
    r = _usuario_do_link(cur, request.args.get("t"))
    cur.close()
    conn.close()
    if not r:
        return jsonify({"success": False, "error": MSG_LINK_INVALIDO}), 400
    return jsonify({"success": True, "nome": r[1], "email": r[2]})


@app.route("/api/senha/definir", methods=["POST"])
def definir_senha():
    if _excedeu_limite_verificacao(_ip() or "?"):
        return jsonify({"success": False, "error": "Muitas tentativas. Aguarde um minuto."}), 429
    data = request.get_json(force=True, silent=True) or {}
    senha = data.get("senha") or ""
    erro = _erro_regra_senha(senha)
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor()
    r = _usuario_do_link(cur, data.get("t"))
    if not r:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": MSG_LINK_INVALIDO}), 400
    usuario_id, nome, email, admin, tinha_senha = r

    senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        "UPDATE usuarios SET senha = %s, senha_alterada = date_trunc('second', NOW()), "
        "link_senha = NULL, alterado = NOW() WHERE usuario = %s",
        (senha_hash, usuario_id)
    )
    _log_usuario(cur, usuario_id, "S", None,
                 "redefinida pelo link" if tinha_senha else "primeira senha, pelo link", _ip())
    conn.commit()
    cur.close()
    conn.close()

    _limpar_falhas_login(email)
    if tinha_senha:
        _avisar_senha_alterada(nome, email)
    return jsonify({"success": True, "admin": admin == "S", "email": email})


# ---- Cadastro de usuarios (subordinados de quem esta logado) ----
@app.route("/api/usuarios", methods=["GET"])
@require_auth
@require_admin
def list_usuarios():
    # Superadmin: os admins de empresa. Admin de empresa: os tecnicos dele
    # (com ?incluir_proprio=1, ele mesmo tambem - pro combo de Tecnicos autorizados).
    proprio = request.args.get("incluir_proprio") == "1" and not request.usuario_super
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT usuario, nome, email, empresa, senha_permanente, observacoes, admin, ativo, "
        "senha IS NULL AS aguardando_senha, ultimo_login, inclusao, alterado "
        "FROM usuarios WHERE master = %s OR (%s AND usuario = %s) ORDER BY nome",
        (request.usuario_id, proprio, request.usuario_id)
    )
    rows = cur.fetchall()
    senha_minima = _senha_permanente_minima(cur)
    cur.close()
    conn.close()

    def data_iso(v):
        return v.isoformat() if v else None

    usuarios = []
    for r in rows:
        usuarios.append({
            "usuario": r["usuario"],
            "nome": r["nome"],
            "email": r["email"],
            "empresa": r["empresa"],
            "senha_permanente": r["senha_permanente"],
            "observacoes": r["observacoes"],
            "admin": r["admin"],
            "ativo": r["ativo"],
            "aguardando_senha": r["aguardando_senha"],
            "ultimo_login": data_iso(r["ultimo_login"]),
            "inclusao": data_iso(r["inclusao"]),
            "alterado": data_iso(r["alterado"]),
        })

    return jsonify({"success": True, "usuarios": usuarios, "super": request.usuario_super,
                    "master_nome": request.usuario_logado, "senha_minima": senha_minima})


# Menor numero de senha permanente que quem esta logado pode dar a um
# subordinado: o superadmin da qualquer um (1 a 5) ao admin de empresa; o admin
# da aos tecnicos do numero dele ate 5.
def _senha_permanente_minima(cur):
    if request.usuario_super:
        return 1
    cur.execute("SELECT senha_permanente FROM usuarios WHERE usuario = %s", (request.usuario_id,))
    r = cur.fetchone()
    v = (r["senha_permanente"] if isinstance(r, dict) else r[0]) if r else None
    return v or 1


def _dados_usuario(data):
    # Le so o que a tela pode informar. "admin" e "master" nao entram aqui.
    nome = (data.get("nome") or "").strip()
    email = _normalizar_email(data.get("email"))
    observacoes = (data.get("observacoes") or "").strip() or None
    ativo = "N" if data.get("ativo") == "N" else "S"
    if not nome or len(nome) > 100:
        return None, "Informe o nome (até 100 caracteres)."
    if not _RE_EMAIL.match(email) or len(email) > 100:
        return None, "Informe um e-mail válido."
    empresa = None
    if request.usuario_super:
        empresa = (data.get("empresa") or "").strip()
        if not empresa or len(empresa) > 100:
            return None, "Informe a empresa (até 100 caracteres)."
    try:
        senha_permanente = int(data.get("senha_permanente"))
    except (TypeError, ValueError):
        senha_permanente = None
    if senha_permanente not in (1, 2, 3, 4, 5):
        return None, "Informe a senha permanente (Senha 1 a Senha 5)."
    return {"nome": nome, "email": email, "observacoes": observacoes, "ativo": ativo,
            "empresa": empresa, "senha_permanente": senha_permanente}, None


# Regras do numero da senha permanente (o trigger tg_biu_usuarios garante as
# mesmas no banco; aqui e pra responder com uma mensagem clara).
def _erro_senha_permanente(cur, senha_permanente, usuario_id=None):
    minima = _senha_permanente_minima(cur)
    if senha_permanente < minima:
        return f"Os técnicos desta empresa usam da Senha {minima} à Senha 5."
    if request.usuario_super and usuario_id:
        cur.execute(
            "SELECT nome FROM usuarios WHERE master = %s AND senha_permanente < %s ORDER BY nome",
            (usuario_id, senha_permanente)
        )
        abaixo = [(r["nome"] if isinstance(r, dict) else r[0]) for r in cur.fetchall()]
        if abaixo:
            return (f"Há técnico desta empresa com senha permanente menor que a Senha {senha_permanente} "
                    f"({', '.join(abaixo)}). Ajuste os técnicos antes.")
    return None


def _resposta_link(ok, erro, texto_ok):
    if ok:
        return jsonify({"success": True, "aviso": texto_ok})
    return jsonify({"success": True, "email_falhou": True,
                    "aviso": f"Salvo, mas o e-mail não foi enviado ({erro}). Use \"Reenviar e-mail\" depois."})


@app.route("/api/usuarios", methods=["POST"])
@require_auth
@require_admin
def add_usuario():
    d, erro = _dados_usuario(request.get_json(force=True, silent=True) or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    # Quem cria decide o tipo: superadmin cria admin de empresa; admin cria tecnico.
    admin = "S" if request.usuario_super else "N"

    conn = get_db()
    cur = conn.cursor()
    erro = _erro_senha_permanente(cur, d["senha_permanente"])
    if erro:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": erro}), 400
    try:
        cur.execute(
            "INSERT INTO usuarios (nome, email, observacoes, admin, ativo, master, empresa, senha_permanente) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING usuario",
            (d["nome"], d["email"], d["observacoes"], admin, d["ativo"], request.usuario_id,
             d["empresa"], d["senha_permanente"])
        )
        novo_id = cur.fetchone()[0]
        if admin == "S":
            # toda conta nasce com o catalogo "Novos", que recebe as maquinas
            cur.execute("INSERT INTO catalogos (conta, catalogo, nome) VALUES (%s, %s, %s)",
                        (novo_id, CATALOGO_NOVOS, NOME_CATALOGO_NOVOS))
        _log_usuario(cur, novo_id, "C", request.usuario_id, d["email"], _ip())
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"success": False, "error": "Já existe um usuário com esse e-mail."}), 409
    finally:
        cur.close()
        conn.close()

    if d["ativo"] != "S":
        return jsonify({"success": True, "aviso": "Usuário criado inativo: o e-mail com o link será enviado quando você reenviar."})
    ok, erro = _enviar_link_senha(novo_id, "convite", request.usuario_id, _ip())
    return _resposta_link(ok, erro, f"Usuário criado. Enviamos para {d['email']} o link para criar a senha.")


@app.route("/api/usuarios/<int:usuario_id>", methods=["PUT"])
@require_auth
@require_admin
def edit_usuario(usuario_id):
    d, erro = _dados_usuario(request.get_json(force=True, silent=True) or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # So os subordinados de quem esta logado.
    cur.execute(
        "SELECT nome, email, observacoes, ativo, empresa, senha_permanente, senha IS NULL AS aguardando "
        "FROM usuarios WHERE usuario = %s AND master = %s",
        (usuario_id, request.usuario_id)
    )
    atual = cur.fetchone()
    if not atual:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Usuário não encontrado"}), 404

    # E-mail: fixo depois de criado. Excecoes: enquanto aguarda a senha (corrigir
    # digitacao) e o superadmin trocando o admin de uma empresa.
    trocou_email = d["email"] != atual["email"]
    if trocou_email and not (atual["aguardando"] or request.usuario_super):
        cur.close()
        conn.close()
        return jsonify({"success": False,
                        "error": "O e-mail não pode ser alterado depois que o usuário criou a senha. "
                                 "Crie outro usuário e desative este."}), 400

    erro = _erro_senha_permanente(cur, d["senha_permanente"], usuario_id)
    if erro:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": erro}), 400

    ip = _ip()
    try:
        cur.execute(
            "UPDATE usuarios SET nome = %s, email = %s, observacoes = %s, ativo = %s, "
            "empresa = %s, senha_permanente = %s, alterado = NOW() WHERE usuario = %s",
            (d["nome"], d["email"], d["observacoes"], d["ativo"], d["empresa"], d["senha_permanente"], usuario_id)
        )
        if trocou_email:
            # Outro dono: a senha antiga deixa de valer e as sessoes caem.
            cur.execute(
                "UPDATE usuarios SET senha = NULL, senha_alterada = date_trunc('second', NOW()), "
                "link_senha = NULL WHERE usuario = %s",
                (usuario_id,)
            )
            _log_usuario(cur, usuario_id, "E", request.usuario_id, f"{atual['email']} -> {d['email']}", ip)
        if d["ativo"] != atual["ativo"]:
            _log_usuario(cur, usuario_id, "A" if d["ativo"] == "S" else "D", request.usuario_id, None, ip)
        mudou = [c for c in ("nome", "observacoes", "empresa", "senha_permanente") if d[c] != atual[c]]
        if mudou:
            _log_usuario(cur, usuario_id, "T", request.usuario_id, ", ".join(mudou), ip)
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"success": False, "error": "Já existe um usuário com esse e-mail."}), 409
    finally:
        cur.close()
        conn.close()

    if trocou_email and d["ativo"] == "S":
        ok, erro = _enviar_link_senha(usuario_id, "convite", request.usuario_id, ip)
        return _resposta_link(ok, erro, f"E-mail alterado. Enviamos para {d['email']} o link para criar a senha.")
    return jsonify({"success": True})


@app.route("/api/usuarios/<int:usuario_id>/link", methods=["POST"])
@require_auth
@require_admin
def reenviar_link_usuario(usuario_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT email, ativo, senha IS NULL FROM usuarios WHERE usuario = %s AND master = %s",
        (usuario_id, request.usuario_id)
    )
    r = cur.fetchone()
    cur.close()
    conn.close()
    if not r:
        return jsonify({"success": False, "error": "Usuário não encontrado"}), 404
    if r[1] != "S":
        return jsonify({"success": False, "error": "Usuário inativo: ative antes de enviar o link."}), 400
    ok, erro = _enviar_link_senha(usuario_id, "convite" if r[2] else "redefinicao", request.usuario_id, _ip())
    if not ok:
        return jsonify({"success": False, "error": f"O e-mail não foi enviado ({erro})."}), 502
    return jsonify({"success": True, "aviso": f"Link enviado para {r[0]}."})


# Usuario nao e excluido, so desativado: o historico (auditoria, log_usuarios,
# tecnicos autorizados) aponta pra ele. Por isso nao existe rota de exclusao.


# ------------------------------------------------------------
# CATALOGOS E DISPOSITIVOS POR CONTA (item 41, entrega 2)
# ------------------------------------------------------------
# Conta = usuario admin da empresa (request.usuario_id de quem esta no painel).
# Cada conta tem os seus catalogos e a sua ficha de cada dispositivo
# (devices_contas: cliente, apelido, observacao, catalogo, ativo, servidor).
# Em devices ficam so os dados da maquina. O superadmin nao tem conta: nao
# ve catalogos nem dispositivos (so a lista "sem conta").
# A ligacao dispositivo x conta nasce sozinha no primeiro acesso remoto que
# der certo de um tecnico da conta (rota de auditoria); aqui nao existe
# inclusao manual - quem pudesse digitar um ID veria dados de maquina alheia.
TAMANHO_NOME_CATALOGO = 10  # catalogos.nome e varchar(10)
# Catalogo fixo de toda conta (criado junto com ela): recebe a maquina no
# primeiro acesso de um tecnico. Nao pode ser renomeado.
CATALOGO_NOVOS = 0
NOME_CATALOGO_NOVOS = "Novos"


@app.route("/api/catalogos", methods=["GET"])
@require_auth
@require_admin_empresa
def list_catalogos():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT catalogo, nome FROM catalogos WHERE conta = %s ORDER BY catalogo", (request.usuario_id,))
    catalogos = [{"catalogo": int(r[0]), "nome": r[1], "fixo": int(r[0]) == CATALOGO_NOVOS}
                 for r in cur.fetchall()]
    cur.close()
    conn.close()
    return jsonify({"success": True, "catalogos": catalogos})


def _nome_catalogo(data):
    nome = (data.get("nome") or "").strip()
    if not nome:
        return None, "Nome obrigatorio"
    if len(nome) > TAMANHO_NOME_CATALOGO:
        return None, f"O nome do catálogo tem no máximo {TAMANHO_NOME_CATALOGO} caracteres"
    return nome, None


@app.route("/api/catalogos", methods=["POST"])
@require_auth
@require_admin_empresa
def add_catalogo():
    nome, erro = _nome_catalogo(request.get_json(force=True, silent=True) or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        # numeracao propria de cada conta
        cur.execute(
            "INSERT INTO catalogos (conta, catalogo, nome) "
            "SELECT %s, COALESCE(MAX(catalogo), 0) + 1, %s FROM catalogos WHERE conta = %s "
            "RETURNING catalogo",
            (request.usuario_id, nome, request.usuario_id)
        )
        novo_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"success": False, "error": "Já existe um catálogo com esse nome."}), 409
    finally:
        cur.close()
        conn.close()
    return jsonify({"success": True, "catalogo": novo_id, "nome": nome})


@app.route("/api/catalogos/<int:catalogo_id>", methods=["PUT"])
@require_auth
@require_admin_empresa
def edit_catalogo(catalogo_id):
    if catalogo_id == CATALOGO_NOVOS:
        return jsonify({"success": False,
                        "error": f"O catálogo \"{NOME_CATALOGO_NOVOS}\" não pode ser renomeado."}), 400
    nome, erro = _nome_catalogo(request.get_json(force=True, silent=True) or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE catalogos SET nome = %s WHERE conta = %s AND catalogo = %s",
                    (nome, request.usuario_id, catalogo_id))
        updated = cur.rowcount
        # o nome do catalogo aparece como etiqueta no MrDeskPro: as fichas mudaram
        cur.execute("UPDATE devices_contas SET atualizado = NOW() WHERE conta = %s AND catalogo = %s",
                    (request.usuario_id, catalogo_id))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"success": False, "error": "Já existe um catálogo com esse nome."}), 409
    finally:
        cur.close()
        conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Catalogo nao encontrado"}), 404
    return jsonify({"success": True})


# ------------------------------------------------------------
# LISTAR dispositivos da conta
# ------------------------------------------------------------
@app.route("/api/devices", methods=["GET"])
@require_auth
@require_admin_empresa
def list_devices():
    catalogo = request.args.get("catalogo")
    filtro_ativo = request.args.get("ativo", "S")
    filtro_servidor = request.args.get("servidor", "N")
    filtro_instalado = request.args.get("instalado", "S")

    if filtro_ativo not in ("S", "N"):
        filtro_ativo = "S"
    if filtro_servidor not in ("S", "N"):
        filtro_servidor = "N"
    if filtro_instalado not in ("S", "N"):
        filtro_instalado = "S"

    try:
        catalogo = int(catalogo)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "catalogo e obrigatorio"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT d.id, dc.cliente, dc.apelido, dc.observacao, dc.usuario, dc.ativo, dc.servidor, dc.catalogo, "
        "d.sistema, d.memoria, d.processador, d.computador, "
        "d.ultima_vez_online, dc.inclusao, dc.atualizado, "
        # item 30: versao do ERP (licencas.id_mrdesk = devices.id) - so a conta da Sysrs
        "CASE WHEN %s THEN l.versao END AS versao_erp, "
        # tempo sem sinal calculado DENTRO do banco (mesmo relogio que gravou
        # ultima_vez_online) - nao depende do relogio/fuso do Python
        "EXTRACT(EPOCH FROM (NOW() - d.ultima_vez_online)) AS segundos_sem_sinal, "
        "EXTRACT(EPOCH FROM (NOW() - d.ultima_atividade)) AS segundos_sem_uso "
        "FROM devices_contas dc JOIN devices d ON d.id = dc.dispositivo "
        "LEFT JOIN licencas l ON l.id_mrdesk = d.id "
        # No catalogo "Novos" os filtros nao valem: e a caixa de entrada, mostra tudo o que chegou.
        "WHERE dc.conta = %s AND dc.catalogo = %s "
        "AND (%s OR (dc.ativo = %s AND dc.servidor = %s AND d.instalado = %s)) "
        # cliente nulo: a ficha aparece pelo apelido
        "ORDER BY COALESCE(dc.cliente, dc.apelido), dc.apelido",
        (request.usuario_sysrs, request.usuario_id, catalogo, catalogo == CATALOGO_NOVOS,
         filtro_ativo, filtro_servidor, filtro_instalado)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Online = recebemos heartbeat ha menos de 40s (o cliente manda a
    # cada ~15-18s, entao 40s da uma folga sem falso "offline").
    LIMITE_ONLINE_SEGUNDOS = 40

    devices = []
    for row in rows:
        ultima = row["ultima_vez_online"]
        online = None
        if row["segundos_sem_sinal"] is not None:
            online = float(row["segundos_sem_sinal"]) <= LIMITE_ONLINE_SEGUNDOS
        devices.append({
            "id": row["id"],
            "cliente": row["cliente"],
            "apelido": row["apelido"],
            "observacao": row["observacao"],
            "sistema": row["sistema"],
            "versao_erp": row["versao_erp"],
            "memoria": row["memoria"],
            "processador": row["processador"],
            "computador": row["computador"],
            "usuario": row["usuario"],
            "ativo": row["ativo"],
            "servidor": row["servidor"],
            "online": online,
            # item 16: ha quanto tempo ninguem mexe no teclado/mouse (None = sem o dado)
            "segundos_sem_uso": int(row["segundos_sem_uso"]) if row["segundos_sem_uso"] is not None else None,
            "ultima_vez_online": ultima.isoformat() if ultima else None,
            "inclusao": row["inclusao"].isoformat() if row["inclusao"] else None,
            "atualizado": row["atualizado"].isoformat() if row["atualizado"] else None
        })

    return jsonify({"success": True, "devices": devices})


# ------------------------------------------------------------
# DISPOSITIVOS SEM CONTA - so o superadmin
# ------------------------------------------------------------
# Maquinas com o MrDesk instalado que nenhum tecnico acessou ainda (sem linha
# em devices_contas). Os MrDeskPro cadastrados em Tecnicos autorizados ficam
# de fora: sao computadores de tecnicos, nao de clientes.
@app.route("/api/devices/sem-conta", methods=["GET"])
@require_auth
@require_super
def devices_sem_conta():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT d.id, d.computador, d.sistema, d.instalado, d.inclusao, d.ultima_vez_online, "
        "EXTRACT(EPOCH FROM (NOW() - d.ultima_vez_online)) AS segundos_sem_sinal "
        "FROM devices d "
        "WHERE NOT EXISTS (SELECT 1 FROM devices_contas dc WHERE dc.dispositivo = d.id) "
        "AND NOT EXISTS (SELECT 1 FROM tecnicos_autorizados t WHERE t.dispositivo = d.id) "
        "ORDER BY d.ultima_vez_online DESC NULLS LAST, d.id"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    devices = [{
        "id": r["id"],
        "computador": r["computador"],
        "sistema": r["sistema"],
        "instalado": r["instalado"],
        "online": float(r["segundos_sem_sinal"]) <= 40 if r["segundos_sem_sinal"] is not None else None,
        "inclusao": r["inclusao"].isoformat() if r["inclusao"] else None,
        "ultima_vez_online": r["ultima_vez_online"].isoformat() if r["ultima_vez_online"] else None,
    } for r in rows]
    return jsonify({"success": True, "devices": devices})


# ------------------------------------------------------------
# PEGAR link de conexao
# ------------------------------------------------------------
# Os links de conexao abrem o app do TECNICO (MrDeskPro). O RustDesk registra
# no Windows um protocolo com o nome do app em minusculas, entao o MrDeskPro
# responde a "mrdeskpro://" (o "mrdesk://" e do app dos clientes, que so
# recebe conexao).
ESQUEMA_CONEXAO = "mrdeskpro"


@app.route("/api/devices/<device_id>/connect", methods=["GET"])
@require_auth
@require_admin_empresa
def get_connect_link(device_id):
    modo = request.args.get("mode", "connect")
    modos_validos = ["connect", "file-transfer", "view-camera", "terminal", "port-forward"]
    if modo not in modos_validos:
        modo = "connect"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(cliente, apelido) FROM devices_contas WHERE dispositivo = %s AND conta = %s",
                (device_id, request.usuario_id))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        link = f"{ESQUEMA_CONEXAO}://{modo}/{device_id}"
        # Item 27: o MrDeskPro (patch 12) usa o nome do cliente como nome da aba
        cliente = (row[0] or "").strip()
        if cliente:
            from urllib.parse import quote
            link += "?cliente=" + quote(cliente, safe="")
        return jsonify({"success": True, "link": link})

    # ID que ainda nao e da conta: permite conectar mesmo assim (botao "Acessar"
    # da busca), desde que tenha o formato de um ID do MrDesk (7 a 10
    # digitos). Se o acesso der certo, o dispositivo entra na conta sozinho.
    if device_id.isdigit() and 7 <= len(device_id) <= 10:
        return jsonify({"success": True, "link": f"{ESQUEMA_CONEXAO}://{modo}/{device_id}"})

    return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404


# ------------------------------------------------------------
# SESSOES VIA RELAY (hbbr) nos ultimos 30 dias
# ------------------------------------------------------------
# A tabela relay_sessoes e preenchida pelo coletar_relay.py (timer do
# systemd, a cada 5 min). Aqui so contamos: sessoes que passaram pelo relay
# x total de conexoes registradas na auditoria no mesmo periodo.
# Grafico do servidor: so o superadmin e a conta da Sysrs.
@app.route("/api/relay", methods=["GET"])
@require_auth
@require_sysrs_ou_super
def relay_stats():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT to_regclass('relay_sessoes') IS NOT NULL")
        tabela_existe = cur.fetchone()[0]
        # Periodo comparado: ultimos 30 dias, mas nunca antes da primeira
        # conexao registrada na auditoria (a auditoria foi criada depois que
        # o relay ja estava em uso; sem isso, o relay teria sessoes de um
        # periodo que a auditoria nao cobre e a comparacao ficaria distorcida).
        cur.execute(
            "SELECT GREATEST(NOW() - INTERVAL '30 days', "
            "COALESCE(MIN(inicio), NOW() - INTERVAL '30 days')) FROM auditoria"
        )
        desde = cur.fetchone()[0]
        relay = 0
        if tabela_existe:
            cur.execute("SELECT COUNT(*) FROM relay_sessoes WHERE inicio >= %s", (desde,))
            relay = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM auditoria WHERE inicio >= %s", (desde,))
        total = cur.fetchone()[0]
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error("Falha ao contar sessoes de relay: %s", e)
        return jsonify({"success": False, "error": "Nao foi possivel contar as sessoes"}), 500

    # Protecao: se por algum motivo houver mais sessoes de relay que conexoes
    # auditadas (ex.: auditoria de um client antigo falhou), limita em 100%.
    percentual = round(min(relay, total) * 100 / total, 1) if total else 0
    return jsonify({
        "success": True,
        "relay": relay,
        "total": total,
        "percentual": percentual,
        "desde": desde.isoformat() if desde else None,
    })


# ------------------------------------------------------------
# LOCALIZAR um ID na conta, ignorando os filtros da tela
# ------------------------------------------------------------
# Usado pelo botao "Acessar" da busca: quando o ID digitado nao aparece na
# lista (por causa do catalogo ou dos filtros Ativo/Instalado/Servidor), a
# tela pergunta aqui onde ele esta, pra explicar no hint o que o esconde.
# So enxerga os dispositivos da conta de quem esta logado.
@app.route("/api/devices/localizar", methods=["GET"])
@require_auth
@require_admin_empresa
def localizar_device():
    device_id = (request.args.get("id") or "").strip()
    if not device_id.isdigit():
        return jsonify({"success": False, "error": "ID invalido"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT d.id, dc.cliente, dc.apelido, dc.ativo, dc.servidor, d.instalado, "
        "dc.catalogo, c.nome AS catalogo_nome "
        "FROM devices_contas dc JOIN devices d ON d.id = dc.dispositivo "
        "JOIN catalogos c ON c.conta = dc.conta AND c.catalogo = dc.catalogo "
        "WHERE dc.dispositivo = %s AND dc.conta = %s",
        (device_id, request.usuario_id)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"success": True, "encontrado": False})
    return jsonify({"success": True, "encontrado": True, "device": dict(row)})


def _device_da_conta(cur, device_id):
    # True se o dispositivo esta ligado a conta de quem esta logado.
    cur.execute("SELECT 1 FROM devices_contas WHERE dispositivo = %s AND conta = %s",
                (device_id, request.usuario_id))
    return cur.fetchone() is not None


# ------------------------------------------------------------
# HISTORICO de auditoria de conexoes de um dispositivo
# ------------------------------------------------------------
# Cada conta ve os acessos dos proprios tecnicos (auditoria.conta) e as
# tentativas sem conta (conta nula: nao chegaram ao login, ou vieram de quem
# nao e tecnico de ninguem - e o que mostra uma tentativa de invasao).
TIPOS_ACESSO_AUDITORIA = {
    0: "Remoto",
    1: "Transferencia de arquivo",
    2: "Port forward",
    3: "Ver camera",
    4: "Terminal",
}


@app.route("/api/devices/<device_id>/auditoria", methods=["GET"])
@require_auth
@require_admin_empresa
def get_auditoria(device_id):
    inicio_str = request.args.get("inicio")
    fim_str = request.args.get("fim")

    try:
        if inicio_str:
            data_inicio = datetime.strptime(inicio_str, "%Y-%m-%d")
        else:
            data_inicio = datetime.now() - timedelta(days=7)
    except ValueError:
        data_inicio = datetime.now() - timedelta(days=7)

    try:
        if fim_str:
            data_fim = datetime.strptime(fim_str, "%Y-%m-%d") + timedelta(days=1)
        else:
            data_fim = datetime.now() + timedelta(days=1)
    except ValueError:
        data_fim = datetime.now() + timedelta(days=1)

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if not _device_da_conta(cur, device_id):
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404
    cur.execute(
        "SELECT inicio, fim, nome, origem, tipo, ip, permissao, autenticacao "
        "FROM auditoria WHERE dispositivo = %s AND inicio >= %s AND inicio < %s "
        "AND (conta = %s OR conta IS NULL) "
        "ORDER BY inicio DESC",
        (device_id, data_inicio, data_fim, request.usuario_id)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    registros = []
    for row in rows:
        duracao_segundos = None
        if row["fim"]:
            duracao_segundos = int((row["fim"] - row["inicio"]).total_seconds())

        registros.append({
            "inicio": row["inicio"].isoformat() if row["inicio"] else None,
            "fim": row["fim"].isoformat() if row["fim"] else None,
            "duracao_segundos": duracao_segundos,
            "nome": row["nome"],
            "origem": row["origem"],
            "permissao": row["permissao"],
            "tipo": TIPOS_ACESSO_AUDITORIA.get(row["tipo"], "Desconhecido") if row["tipo"] is not None else None,
            "autenticacao": row["autenticacao"],
            "ip": row["ip"],
        })

    return jsonify({"success": True, "registros": registros})


# ------------------------------------------------------------
# EDITAR a ficha do dispositivo na conta
# ------------------------------------------------------------
# Cliente pode ficar vazio (nulo): as telas mostram so o apelido.
@app.route("/api/devices/<device_id>", methods=["PUT"])
@require_auth
@require_admin_empresa
def edit_device(device_id):
    data = request.get_json(force=True, silent=True) or {}
    cliente = (data.get("cliente") or "").strip() or None
    apelido = (data.get("apelido") or "").strip()
    # a tela de edicao nao manda a observacao: so mexe nela se vier
    tem_observacao = "observacao" in data
    observacao = data.get("observacao")
    ativo = data.get("ativo", "S")
    servidor = data.get("servidor", "N")

    if ativo not in ("S", "N"):
        ativo = "S"
    if servidor not in ("S", "N"):
        servidor = "N"
    if not apelido:
        return jsonify({"success": False, "error": "Informe o apelido"}), 400
    if len(apelido) > 100 or (cliente and len(cliente) > 100):
        return jsonify({"success": False, "error": "Cliente e apelido têm no máximo 100 caracteres"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE devices_contas SET cliente=%s, apelido=%s, "
        "observacao = CASE WHEN %s THEN %s ELSE observacao END, ativo=%s, servidor=%s, "
        "usuario=%s, atualizado=NOW() WHERE dispositivo=%s AND conta=%s",
        (cliente, apelido, tem_observacao, observacao, ativo, servidor, request.usuario_logado,
         device_id, request.usuario_id)
    )
    conn.commit()
    updated = cur.rowcount
    cur.close()
    conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404

    return jsonify({"success": True})


# ------------------------------------------------------------
# LIBERAR NOVA MAQUINA (item 9) - so a conta da Sysrs. Apaga devices.uuid; o
# proximo contato do MrDesk (heartbeat em segundos) grava o uuid novo.
# ------------------------------------------------------------
@app.route("/api/devices/<device_id>/liberar-maquina", methods=["POST"])
@require_auth
@require_sysrs
def liberar_maquina(device_id):
    conn = get_db()
    cur = conn.cursor()
    atualizado = 0
    if _device_da_conta(cur, device_id):
        cur.execute("UPDATE devices SET uuid = NULL WHERE id = %s", (device_id,))
        conn.commit()
        atualizado = cur.rowcount
    cur.close()
    conn.close()
    if atualizado == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404
    _uuid_ultimo_log.pop(device_id, None)
    print(f"maquina liberada: dispositivo {device_id} por {getattr(request, 'usuario_logado', '?')}",
          file=sys.stderr, flush=True)
    return jsonify({"success": True})


# ------------------------------------------------------------
# LICENCA MR1 do dispositivo (item 30) - so a conta da Sysrs. Liga a licenca
# do ERP (licencas.id_mrdesk) ao dispositivo, pra coluna "Versao MR1" da lista.
# Busca pelo CNPJ, so licencas com antigo = 'N'. Um dispositivo tem no maximo
# uma licenca (ligar outra desliga a anterior); uma licenca ja ligada a outro
# dispositivo passa pra este.
# ------------------------------------------------------------
def _licenca_json(r):
    return {"cnpj": r["cnpj"], "serial": r["serial"], "nome": r["nome"], "versao": r["versao"],
            "ativa": r["ativa"], "id_mrdesk": r["id_mrdesk"]}


@app.route("/api/licencas", methods=["GET"])
@require_auth
@require_sysrs
def buscar_licencas():
    cnpj = "".join(c for c in (request.args.get("cnpj") or "") if c.isalnum()).upper()
    if not cnpj:
        return jsonify({"success": False, "error": "Informe o CNPJ"}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT cnpj, serial, nome, versao, ativa, id_mrdesk FROM licencas "
        "WHERE cnpj = %s AND antigo = 'N' ORDER BY ativa DESC, nome, serial",
        (cnpj[:14],)
    )
    licencas = [_licenca_json(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return jsonify({"success": True, "licencas": licencas})


@app.route("/api/devices/<device_id>/licenca", methods=["GET"])
@require_auth
@require_sysrs
def licenca_do_device(device_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT cnpj, serial, nome, versao, ativa, id_mrdesk FROM licencas WHERE id_mrdesk = %s",
                (device_id,))
    r = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify({"success": True, "licenca": _licenca_json(r) if r else None})


@app.route("/api/devices/<device_id>/licenca", methods=["PUT", "DELETE"])
@require_auth
@require_sysrs
def ligar_licenca(device_id):
    data = request.get_json(silent=True) or {}
    cnpj = "".join(c for c in str(data.get("cnpj") or "") if c.isalnum()).upper()
    serial = str(data.get("serial") or "").strip()
    if request.method == "PUT" and (not cnpj or not serial):
        return jsonify({"success": False, "error": "Informe o CNPJ e o serial"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        if not _device_da_conta(cur, device_id):
            return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404
        # um dispositivo tem no maximo uma licenca: desliga a atual
        cur.execute("UPDATE licencas SET id_mrdesk = NULL WHERE id_mrdesk = %s", (device_id,))
        if request.method == "PUT":
            cur.execute(
                "UPDATE licencas SET id_mrdesk = %s WHERE cnpj = %s AND serial = %s AND antigo = 'N'",
                (device_id, cnpj, serial)
            )
            if cur.rowcount == 0:
                conn.rollback()
                return jsonify({"success": False, "error": "Licença não encontrada"}), 404
        conn.commit()
    finally:
        cur.close()
        conn.close()
    return jsonify({"success": True})


# ------------------------------------------------------------
# MOVER dispositivo de catalogo (dentro da conta)
# ------------------------------------------------------------
@app.route("/api/devices/<device_id>/catalogo", methods=["PUT"])
@require_auth
@require_admin_empresa
def mover_catalogo(device_id):
    data = request.get_json(force=True, silent=True) or {}
    try:
        novo_catalogo = int(data.get("catalogo"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "catalogo e obrigatorio"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE devices_contas SET catalogo=%s, usuario=%s, atualizado=NOW() "
            "WHERE dispositivo=%s AND conta=%s",
            (novo_catalogo, request.usuario_logado, device_id, request.usuario_id)
        )
        conn.commit()
        updated = cur.rowcount
    except psycopg2.errors.ForeignKeyViolation:
        # fk_devices_contas_catalogo: o catalogo nao e desta conta
        conn.rollback()
        return jsonify({"success": False, "error": "Catalogo nao encontrado"}), 404
    finally:
        cur.close()
        conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404

    return jsonify({"success": True})


# ------------------------------------------------------------
# REMOVER o dispositivo da conta
# ------------------------------------------------------------
# Apaga so a ligacao (a ficha desta conta). O dispositivo, o historico de
# auditoria e a ligacao com outras contas continuam. Se um tecnico da conta
# acessar a maquina de novo, ela volta (com ficha nova).
@app.route("/api/devices/<device_id>", methods=["DELETE"])
@require_auth
@require_admin_empresa
def delete_device(device_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices_contas WHERE dispositivo = %s AND conta = %s",
                (device_id, request.usuario_id))
    conn.commit()
    deleted = cur.rowcount
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404

    return jsonify({"success": True})


# ------------------------------------------------------------
# VERSAO DO ERP (item 30) - chamada pelo processo de build/atualizacao do ERP
# ------------------------------------------------------------
# GET ou POST /api/licencas/versao com cnpj, serial e versao (na URL, como o
# ERP ja chama o licenca.php: ?cnpj=...&serial=...&versao=...; ou em JSON ou
# formulario) e usuario/senha por autenticacao basica do HTTP (no Indy:
# Request.Username / Request.Password com BasicAuthentication = True).
# O usuario e a senha ficam no config.py (ERP_API_USUARIO / ERP_API_SENHA);
# sem eles configurados a rota recusa tudo.
# So atualiza quando os 3 campos vem preenchidos e a versao tem so numeros e
# pontos; licenca inexistente e ignorada. No PostgreSQL o gatilho
# tgl_bu_licencas NAO grava historico em versoes (trecho comentado na funcao):
# a propria rota guarda a versao anterior em versoes, com a data da troca.
def _erp_autorizado():
    usuario = getattr(config, "ERP_API_USUARIO", None)
    senha = getattr(config, "ERP_API_SENHA", None)
    auth = request.authorization
    if not usuario or not senha or not auth or auth.type != "basic":
        return False
    return (hmac.compare_digest((auth.username or "").encode(), str(usuario).encode())
            and hmac.compare_digest((auth.password or "").encode(), str(senha).encode()))


@app.route("/api/licencas/versao", methods=["GET", "POST"])
def licenca_versao():
    if not _erp_autorizado():
        return (jsonify({"success": False, "error": "Nao autorizado"}), 401,
                {"WWW-Authenticate": 'Basic realm="MrDesk"'})

    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        data = {}

    def campo(nome):
        valor = data.get(nome)
        if valor is None:
            valor = request.values.get(nome)
        return str(valor).strip() if valor is not None else ""

    # so letras e numeros (tira pontos, barra e traco; CNPJ novo pode ter letras)
    cnpj = "".join(c for c in campo("cnpj") if c.isalnum()).upper()
    serial = campo("serial")
    versao = campo("versao")
    if not cnpj or not serial or not versao:
        return jsonify({"success": True, "atualizado": False, "motivo": "campos vazios"})
    if (len(cnpj) > 14 or len(serial) > 20 or len(versao) > 15
            or not all(parte.isdigit() for parte in versao.split("."))):
        return jsonify({"success": False, "error": "Dados invalidos"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT versao FROM licencas WHERE cnpj = %s AND serial = %s FOR UPDATE",
                    (cnpj, serial))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return jsonify({"success": True, "atualizado": False, "motivo": "licenca nao encontrada"})
        if row[0] == versao:
            conn.rollback()
            return jsonify({"success": True, "atualizado": False, "motivo": "mesma versao"})
        if row[0] is not None:
            # historico: guarda a versao anterior com a data da troca (se ja
            # existir - cliente voltou pra ela e subiu de novo - atualiza a data)
            cur.execute(
                "INSERT INTO versoes (cnpj, serial, versao, data) VALUES (%s, %s, %s, NOW()) "
                "ON CONFLICT (cnpj, serial, versao) DO UPDATE SET data = NOW()",
                (cnpj, serial, row[0])
            )
        cur.execute("UPDATE licencas SET versao = %s WHERE cnpj = %s AND serial = %s",
                    (versao, cnpj, serial))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"versao do ERP nao gravada ({cnpj}/{serial} -> {versao}): {e}",
              file=sys.stderr, flush=True)
        return jsonify({"success": False, "error": "Erro ao gravar"}), 500
    finally:
        cur.close()
        conn.close()
    return jsonify({"success": True, "atualizado": True})


# ------------------------------------------------------------
# MAQUINA DO DISPOSITIVO (item 9) - devices.uuid
# ------------------------------------------------------------
# Heartbeat, sysinfo e auditoria nao tem senha (desenho do RustDesk). O MrDesk
# manda em todos o "uuid" da maquina (codigo da instalacao do Windows). O
# primeiro contato grava em devices.uuid; dai em diante aviso com uuid
# diferente (ou sem uuid) e recusado e vai pro log - assim ninguem grava
# auditoria falsa nem mexe no on-line/sistema de um ID sem conhecer o uuid.
# Reinstalou o Windows (mesmo ID, uuid novo): o computador fica off-line no
# painel ate o admin usar "Liberar nova maquina" (apaga o uuid; o proximo
# contato grava o novo).
_UUID_LOG_INTERVALO = 600  # segundos entre linhas de log do mesmo ID
_uuid_ultimo_log = {}


def _uuid_recebido(data):
    valor = data.get("uuid")
    return str(valor)[:64] if valor else None


def _maquina_confere(cur, device_id, uuid_env, origem):
    """True se o aviso pode ser gravado. Grava o uuid no primeiro contato.
    Dispositivo inexistente: True (quem chamou decide se cria)."""
    cur.execute("SELECT uuid FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    if not row:
        return True
    guardado = row[0]
    if guardado is None:
        if uuid_env:
            cur.execute("UPDATE devices SET uuid = %s WHERE id = %s AND uuid IS NULL",
                        (uuid_env, device_id))
        return True
    if uuid_env == guardado:
        return True
    agora = time.time()
    if agora - _uuid_ultimo_log.get(device_id, 0) >= _UUID_LOG_INTERVALO:
        _uuid_ultimo_log[device_id] = agora
        ip = request.headers.get("X-Real-IP") or request.remote_addr
        print(f"maquina diferente recusada ({origem}): dispositivo {device_id}, "
              f"uuid recebido {uuid_env!r}, IP {ip} - se o Windows foi reinstalado, "
              f"use 'Liberar nova maquina' no painel", file=sys.stderr, flush=True)
    return False


# ------------------------------------------------------------
# HEARTBEAT / SYSINFO - recebidos diretamente do cliente MrDesk
# (nao passam pelo hbbs, o cliente manda direto pro "Servidor API"
# configurado nele). Sem autenticacao, por desenho do proprio
# RustDesk - confirmado por teste real em 24/09/2026.
# ------------------------------------------------------------
@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get("id")
    if not device_id:
        return jsonify({})

    # Item 16: o MrDesk com o patch manda ha quantos segundos o teclado/mouse
    # estao parados ("mrdesk_ocioso"). Guardamos a hora da ultima atividade.
    # Sem o campo (MrDesk sem o patch), ultima_atividade nao muda.
    ocioso = data.get("mrdesk_ocioso")
    try:
        ocioso = int(ocioso) if ocioso is not None else None
        if ocioso is not None and not (0 <= ocioso <= 60 * 60 * 24 * 365):
            ocioso = None
    except (TypeError, ValueError):
        ocioso = None

    uuid_env = _uuid_recebido(data)
    conn = get_db()
    cur = conn.cursor()
    if not _maquina_confere(cur, device_id, uuid_env, "heartbeat"):
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({})
    cur.execute("SELECT id FROM devices WHERE id = %s", (device_id,))
    if cur.fetchone():
        # Item 34: o heartbeat traz as conexoes ativas ("conns" = conn_id; sem o
        # campo = nenhuma). Acesso aberto que nao esta mais na lista terminou sem
        # aviso de fechamento (MrDesk morto, queda de energia...): fecha agora.
        # So mexe em acesso que ja passou do login (origem preenchida) e aberto
        # ha mais de 1 minuto - quem esta na tela de senha nunca e fechado aqui.
        ativos = data.get("conns")
        if not isinstance(ativos, list):
            ativos = []
        try:
            ativos = [int(c) % ACESSO_FATOR for c in ativos][:200]
        except (TypeError, ValueError):
            ativos = None
        if ativos is not None:
            cur.execute(
                "UPDATE auditoria SET fim = NOW() WHERE dispositivo = %s AND fim IS NULL "
                "AND origem IS NOT NULL AND inicio < NOW() - INTERVAL '1 minute' "
                "AND NOT ((acesso %% %s) = ANY(%s::bigint[]))",
                (str(device_id)[:20], ACESSO_FATOR, ativos)
            )
        if ocioso is None:
            cur.execute("UPDATE devices SET ultima_vez_online = NOW() WHERE id = %s", (device_id,))
        else:
            cur.execute(
                "UPDATE devices SET ultima_vez_online = NOW(), "
                "ultima_atividade = NOW() - make_interval(secs => %s) WHERE id = %s",
                (ocioso, device_id)
            )
    else:
        # Dispositivo desconhecido: cria um registro minimo.
        # O /api/sysinfo (que chega poucos minutos depois) completa
        # os dados (hostname, SO, etc).
        # (item 41: fica "sem conta" ate o primeiro acesso de um tecnico)
        cur.execute(
            "INSERT INTO devices (id, ultima_vez_online, uuid) "
            "VALUES (%s, NOW(), %s) ON CONFLICT (id) DO NOTHING",
            (device_id, uuid_env)
        )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({})


@app.route("/api/sysinfo", methods=["POST"])
def sysinfo():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get("id")
    if not device_id:
        return jsonify({})

    # O MrDesk ja manda isso no sysinfo (codigo do RustDesk, get_sysinfo):
    # os ("windows / Windows 10 Pro - 10.0.19045"), memory ("8GB"),
    # cpu ("Intel..., 1.8GHz, 8/4 cores") e hostname. Colunas criadas em 01/10.
    def _txt(valor, tamanho):
        valor = (str(valor).strip() if valor is not None else "")
        return valor[:tamanho] or None
    sistema = _txt(data.get("os"), 150)
    memoria = _txt(data.get("memory"), 20)
    processador = _txt(data.get("cpu"), 150)
    computador = _txt(data.get("hostname"), 100)

    # Campo novo do client (patch aplicado em 26/09/2026): informa se o
    # RustDesk esta rodando instalado ("S") ou portatil/nao instalado ("N").
    # Clients antigos (sem o patch) nao mandam esse campo - nesse caso
    # nao mexemos na coluna, que ja tem DEFAULT 'S'.
    instalado = data.get("installed")
    if instalado not in ("S", "N"):
        instalado = None

    uuid_env = _uuid_recebido(data)
    conn = get_db()
    cur = conn.cursor()
    if not _maquina_confere(cur, device_id, uuid_env, "sysinfo"):
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({})
    cur.execute("SELECT id FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()

    if row:
        # Ja existe: atualiza os dados da maquina e marca que esta vivo agora
        # (a ficha - cliente, apelido - e de cada conta, em devices_contas).
        # instalado so e sobrescrito quando o
        # client manda o campo (CASE mantem o valor atual quando vier NULL) -
        # um unico UPDATE, priorizando performance (1 round-trip em vez de 2).
        # (observacao deixou de receber o SO em 01/10 - o SO vai pra coluna sistema)
        cur.execute(
            "UPDATE devices SET sistema = COALESCE(%s, sistema), memoria = COALESCE(%s, memoria), "
            "processador = COALESCE(%s, processador), computador = COALESCE(%s, computador), "
            "ultima_vez_online = NOW(), "
            "instalado = CASE WHEN %s IS NOT NULL THEN %s ELSE instalado END "
            "WHERE id = %s",
            (sistema, memoria, processador, computador, instalado, instalado, device_id)
        )
    else:
        cur.execute(
            "INSERT INTO devices (id, ultima_vez_online, instalado, "
            "sistema, memoria, processador, computador, uuid) "
            "VALUES (%s, NOW(), COALESCE(%s, 'S'), %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
            (device_id, instalado, sistema, memoria, processador, computador, uuid_env)
        )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({})


# ------------------------------------------------------------
# TECNICOS AUTORIZADOS (item 6A) - so o admin gerencia
# ------------------------------------------------------------
# Cada linha = um MrDeskPro (ID) de um tecnico (usuario do painel). O MrDesk
# do cliente so aceita conexao de MrDeskPro cadastrado aqui, com a linha
# ativa E o usuario dono ativo. Nao se exclui: desativa.
# O ID precisa existir em devices (fk_tecnico_device) - o MrDeskPro entra em
# devices sozinho pelo heartbeat, basta ter ficado on-line uma vez.
TAMANHO_ID_DISPOSITIVO = 20  # padrao: tudo que representa device e varchar(20)


def _normalizar_id(valor):
    # IDs sao so numeros; aceita digitado com espacos ("207 575 694").
    return "".join(str(valor or "").split())


# Item 41: so o admin de empresa gerencia (o superadmin nao), e so os
# MrDeskPro dele mesmo e dos tecnicos dele.
def _usuario_da_conta(cur, usuario_id):
    # True se o usuario e o admin logado ou um tecnico dele.
    cur.execute("SELECT 1 FROM usuarios WHERE usuario = %s AND (usuario = %s OR master = %s)",
                (usuario_id, request.usuario_id, request.usuario_id))
    return cur.fetchone() is not None


@app.route("/api/tecnicos", methods=["GET"])
@require_auth
@require_admin_empresa
def list_tecnicos():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT t.dispositivo, t.usuario, t.descricao, t.ativo, t.inclusao, t.alterado, "
        "u.nome AS usuario_nome, u.ativo AS usuario_ativo, "
        "d.ultima_vez_online "
        "FROM tecnicos_autorizados t "
        "JOIN usuarios u ON u.usuario = t.usuario "
        "LEFT JOIN devices d ON d.id = t.dispositivo "
        "WHERE u.usuario = %s OR u.master = %s "
        "ORDER BY u.nome, t.dispositivo",
        (request.usuario_id, request.usuario_id)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    tecnicos = []
    for r in rows:
        tecnicos.append({
            "dispositivo": r["dispositivo"],
            "usuario": r["usuario"],
            "usuario_nome": r["usuario_nome"],
            "usuario_ativo": "N" if r["usuario_ativo"] == "N" else "S",
            "descricao": r["descricao"],
            "ativo": "N" if r["ativo"] == "N" else "S",
            "ultima_vez_online": r["ultima_vez_online"].isoformat() if r["ultima_vez_online"] else None,
        })
    return jsonify({"success": True, "tecnicos": tecnicos})


def _dados_tecnico(data):
    dispositivo = _normalizar_id(data.get("dispositivo"))
    descricao = (data.get("descricao") or "").strip() or None
    ativo = "N" if data.get("ativo") == "N" else "S"
    try:
        usuario = int(data.get("usuario"))
    except (TypeError, ValueError):
        usuario = None
    if not dispositivo or usuario is None:
        return None, "ID do MrDeskPro e técnico são obrigatórios"
    if len(dispositivo) > TAMANHO_ID_DISPOSITIVO:
        return None, f"O ID tem no máximo {TAMANHO_ID_DISPOSITIVO} caracteres"
    if descricao and len(descricao) > 100:
        return None, "A descrição tem no máximo 100 caracteres"
    return (dispositivo, usuario, descricao, ativo), None


def _erro_integridade_tecnico(e):
    constraint = getattr(e.diag, "constraint_name", None)
    if constraint == "fk_tecnico_device":
        return "ID não encontrado nos dispositivos: o MrDeskPro precisa ter ficado on-line ao menos uma vez."
    if constraint == "fk_tecnico_usuario":
        return "Técnico (usuário) não encontrado."
    if constraint == "pk_tecnicos_autorizados":
        return "Esse ID já está cadastrado."
    return "Não foi possível salvar."


@app.route("/api/tecnicos", methods=["POST"])
@require_auth
@require_admin_empresa
def add_tecnico():
    dados, erro = _dados_tecnico(request.get_json() or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor()
    if not _usuario_da_conta(cur, dados[1]):
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Técnico (usuário) não encontrado."}), 400
    try:
        cur.execute(
            "INSERT INTO tecnicos_autorizados (dispositivo, usuario, descricao, ativo) "
            "VALUES (%s, %s, %s, %s)",
            dados
        )
        conn.commit()
        return jsonify({"success": True})
    except psycopg2.IntegrityError as e:
        conn.rollback()
        return jsonify({"success": False, "error": _erro_integridade_tecnico(e)}), 409
    finally:
        cur.close()
        conn.close()


# Editar (inclusive trocar o ID: e a chave, mas nada aponta pra essa tabela).
@app.route("/api/tecnicos/<dispositivo_original>", methods=["PUT"])
@require_auth
@require_admin_empresa
def edit_tecnico(dispositivo_original):
    dados, erro = _dados_tecnico(request.get_json() or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400
    dispositivo, usuario, descricao, ativo = dados

    conn = get_db()
    cur = conn.cursor()
    if not _usuario_da_conta(cur, usuario):
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Técnico (usuário) não encontrado."}), 400
    try:
        # so linhas que hoje sao da conta de quem esta logado
        cur.execute(
            "UPDATE tecnicos_autorizados SET dispositivo=%s, usuario=%s, descricao=%s, "
            "ativo=%s, alterado=NOW() WHERE dispositivo=%s "
            "AND usuario IN (SELECT usuario FROM usuarios WHERE usuario = %s OR master = %s)",
            (dispositivo, usuario, descricao, ativo, _normalizar_id(dispositivo_original),
             request.usuario_id, request.usuario_id)
        )
        conn.commit()
        updated = cur.rowcount
    except psycopg2.IntegrityError as e:
        conn.rollback()
        return jsonify({"success": False, "error": _erro_integridade_tecnico(e)}), 409
    finally:
        cur.close()
        conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Técnico não encontrado"}), 404
    return jsonify({"success": True})


# ------------------------------------------------------------
# VERIFICAR TECNICO - consultado pelo MrDesk do cliente (sem login)
# ------------------------------------------------------------
# O MrDesk (patch no RustDesk) pergunta, antes de validar a senha, se o
# MrDeskPro que esta conectando e autorizado:
#   POST {"id": <ID do MrDesk>, "peer": <ID de quem conecta>}
#   -> {"autorizado": true|false}
# Responde so sim/nao pro ID perguntado, nunca a lista. Limite de consultas
# por IP (em memoria, por worker do gunicorn) pra dificultar varredura.
# Qualquer resposta que nao seja HTTP 200 com {"autorizado": ...} o MrDesk
# trata como "servidor fora" (usa o cache de 72h, se tiver).
# Item 6B (cinco senhas permanentes): a conta do tecnico tem um numero de
# acesso (usuarios.senha_permanente do tecnico, 1 a 5; 1 = reservada, Sysrs) e o MrDesk
# confere so a senha permanente daquele numero. O MrDesk 1.4.11+ manda
# "senhas": 5 nas duas consultas e recebe o numero:
#   verificar -> {"autorizado": true, "acesso": N}
#   lista     -> codigos SHA-256 de "<ID do MrDesk>:<ID do MrDeskPro>:<N>"
# MrDesk mais antigo (sem "senhas") so conhece a senha 1: pra ele, tecnico de
# acesso diferente de 1 e "nao autorizado" e fica fora da lista.
LIMITE_VERIFICACOES_POR_MINUTO = 60
# numero da senha permanente do proprio usuario (tecnico ou admin de empresa)
_SQL_ACESSO_TECNICO = "COALESCE(u.senha_permanente, 1)"
_SQL_TECNICOS_ATIVOS = (
    "tecnicos_autorizados t JOIN usuarios u ON u.usuario = t.usuario "
    "LEFT JOIN usuarios m ON m.usuario = u.master "
    "WHERE t.ativo = 'S' AND u.ativo = 'S' AND COALESCE(m.ativo, 'S') = 'S'"
)


def _mrdesk_cinco_senhas(data):
    try:
        return int(data.get("senhas") or 0) >= 5
    except (TypeError, ValueError):
        return False
_verificacoes_por_ip = {}
_verificacoes_lock = threading.Lock()


def _excedeu_limite_verificacao(ip):
    agora = time.time()
    with _verificacoes_lock:
        janela = [t for t in _verificacoes_por_ip.get(ip, []) if agora - t < 60]
        janela.append(agora)
        _verificacoes_por_ip[ip] = janela
        if len(_verificacoes_por_ip) > 10000:  # nao deixa crescer sem fim
            for chave in [k for k, v in _verificacoes_por_ip.items() if not v or agora - v[-1] >= 60]:
                del _verificacoes_por_ip[chave]
        return len(janela) > LIMITE_VERIFICACOES_POR_MINUTO


@app.route("/api/tecnicos/verificar", methods=["POST"])
def verificar_tecnico():
    ip = request.headers.get("X-Real-IP") or request.remote_addr or "?"
    if _excedeu_limite_verificacao(ip):
        # sem a chave "autorizado": o MrDesk trata como "sem resposta" (usa o cache),
        # e nao como bloqueio
        return jsonify({"motivo": "limite"}), 429

    data = request.get_json(force=True, silent=True) or {}
    peer = _normalizar_id(data.get("peer"))
    if not peer or len(peer) > TAMANHO_ID_DISPOSITIVO:
        return jsonify({"autorizado": False})

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT " + _SQL_ACESSO_TECNICO + " FROM " + _SQL_TECNICOS_ATIVOS + " AND t.dispositivo = %s",
                (peer,))
    r = cur.fetchone()
    cur.close()
    conn.close()
    if not r:
        return jsonify({"autorizado": False})
    acesso = r[0]
    if acesso != 1 and not _mrdesk_cinco_senhas(data):
        # MrDesk anterior a 1.4.11 so conhece a senha 1: liberar deixaria o
        # tecnico de outra conta entrar com a senha da Sysrs.
        return jsonify({"autorizado": False})
    return jsonify({"autorizado": True, "acesso": acesso})


# ------------------------------------------------------------
# LISTA DE TECNICOS PRO CACHE DO MRDESK (item 23) - sem login
# ------------------------------------------------------------
# O MrDesk baixa 1x por dia (e a cada acesso) a lista de tecnicos autorizados e
# usa essa lista quando o servidor nao responde (validade 15 dias).
#   POST {"id": <ID do MrDesk>} -> {"lista": [codigos], "validade_dias": 15}
# Cada codigo = SHA-256 de "<ID do MrDesk>:<ID do MrDeskPro>" (hex). Nao revela
# os IDs dos tecnicos e so serve naquele cliente. Mesmo limite por IP da
# verificacao.
VALIDADE_LISTA_DIAS = 15


@app.route("/api/tecnicos/lista", methods=["POST"])
def lista_tecnicos_cache():
    import hashlib
    ip = request.headers.get("X-Real-IP") or request.remote_addr or "?"
    if _excedeu_limite_verificacao(ip):
        return jsonify({"motivo": "limite"}), 429

    data = request.get_json(force=True, silent=True) or {}
    cliente = _normalizar_id(data.get("id"))
    if not cliente or len(cliente) > TAMANHO_ID_DISPOSITIVO:
        return jsonify({"motivo": "id"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT t.dispositivo, " + _SQL_ACESSO_TECNICO + " FROM " + _SQL_TECNICOS_ATIVOS)
    tecnicos = cur.fetchall()
    cur.close()
    conn.close()

    if _mrdesk_cinco_senhas(data):
        textos = [f"{cliente}:{tec}:{acesso}" for tec, acesso in tecnicos]
    else:
        textos = [f"{cliente}:{tec}" for tec, acesso in tecnicos if acesso == 1]
    lista = sorted(hashlib.sha256(t.encode()).hexdigest() for t in textos)
    return jsonify({"lista": lista, "validade_dias": VALIDADE_LISTA_DIAS})


# ------------------------------------------------------------
# LOGIN E CATALOGO DE ENDERECOS DO MRDESKPRO (item 24)
# ------------------------------------------------------------
# O MrDeskPro (login liberado so nele) usa o "catalogo de enderecos" nativo do
# RustDesk no modo simples ("legacy"): /api/login, /api/currentUser,
# /api/logout e GET /api/ab. /api/ab/personal NAO existe (404) - e assim que o
# MrDeskPro sabe que deve usar o modo simples.
# - Login com e-mail/senha (item 41; o campo "usuario" do MrDeskPro recebe o
#   e-mail), usuario ativo, admin da empresa dele ativo, e SO a partir de um
#   MrDeskPro cadastrado em Tecnicos autorizados pra esse mesmo usuario.
# - Sessao vale 30 dias (depois, entrar de novo). Usuario, admin da empresa
#   ou MrDeskPro desativado, ou senha trocada -> a sessao cai na proxima
#   conferencia.
# - Catalogo (item 41): os dispositivos ativos da conta do tecnico; o tecnico
#   pode renomear (apelido) e trocar a etiqueta (catalogo); sem senha/hash (o
#   RustDesk permite guardar atalho de senha no catalogo).
serializer_pro = URLSafeTimedSerializer(config.APP_SECRET_KEY, salt="mrdeskpro-catalogo")
VALIDADE_SESSAO_PRO = 60 * 60 * 24 * 30  # 30 dias
LIMITE_LOGIN_PRO_POR_MINUTO = 10
_login_pro_por_ip = {}


def _excedeu_limite_login_pro(ip):
    agora = time.time()
    with _verificacoes_lock:
        janela = [t for t in _login_pro_por_ip.get(ip, []) if agora - t < 60]
        janela.append(agora)
        _login_pro_por_ip[ip] = janela
        if len(_login_pro_por_ip) > 10000:
            for chave in [k for k, v in _login_pro_por_ip.items() if not v or agora - v[-1] >= 60]:
                del _login_pro_por_ip[chave]
        return len(janela) > LIMITE_LOGIN_PRO_POR_MINUTO


def _usuario_pro_valido(cur, usuario_id, dispositivo, emitido=None):
    # usuario ativo + admin da empresa dele ativo + esse MrDeskPro ativo e dele
    # + (se "emitido" vier) senha nao trocada depois da sessao criada.
    # Devolve (nome, admin, email) ou None.
    cur.execute(
        "SELECT u.nome, u.admin, u.email FROM usuarios u "
        "JOIN tecnicos_autorizados t ON t.usuario = u.usuario "
        "LEFT JOIN usuarios m ON m.usuario = u.master "
        "WHERE u.usuario = %s AND u.ativo = 'S' AND COALESCE(m.ativo, 'S') = 'S' "
        "AND t.dispositivo = %s AND t.ativo = 'S' "
        "AND (%s::bigint IS NULL OR u.senha_alterada IS NULL "
        "     OR u.senha_alterada <= to_timestamp(%s::bigint)::timestamp)",
        (usuario_id, dispositivo, emitido, emitido)
    )
    return cur.fetchone()


def _payload_usuario_pro(nome, admin, email):
    return {"name": nome, "display_name": nome, "email": email or "",
            "status": 1, "is_admin": admin == "S"}


def _sessao_pro():
    # Le o "Bearer" do MrDeskPro. Devolve (usuario_id, dispositivo, linha) ou None.
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None
    try:
        dados, emitido = serializer_pro.loads(token, max_age=VALIDADE_SESSAO_PRO, return_timestamp=True)
    except (SignatureExpired, BadSignature):
        return None
    conn = get_db()
    cur = conn.cursor()
    linha = _usuario_pro_valido(cur, dados.get("u"), dados.get("d"), int(emitido.timestamp()))
    cur.close()
    conn.close()
    if not linha:
        return None
    return dados.get("u"), dados.get("d"), linha


@app.route("/api/login-options", methods=["GET"])
def login_options_pro():
    return jsonify([])


def login_pro():
    # Chamado pelo /api/login do painel quando o pedido vem do MrDeskPro
    # (o RustDesk manda "id" e "uuid" junto com usuario/senha).
    ip = request.headers.get("X-Real-IP") or request.remote_addr or "?"
    if _excedeu_limite_login_pro(ip):
        return jsonify({"error": "Muitas tentativas. Aguarde um minuto e tente de novo."}), 429

    data = request.get_json(force=True, silent=True) or {}
    nome = _normalizar_email(data.get("username"))  # o login e o e-mail
    senha = data.get("password") or ""
    dispositivo = _normalizar_id(data.get("id"))
    if not nome or not senha or not dispositivo:
        return jsonify({"error": "Informe e-mail e senha."}), 400
    if _login_bloqueado(nome):
        return jsonify({"error": "Muitas tentativas. Aguarde alguns minutos e tente de novo."}), 429

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT usuario, nome, senha, admin, email FROM usuarios WHERE email = %s AND ativo = 'S'", (nome,))
    user = cur.fetchone()
    ok_senha = bool(user) and _senha_confere(senha, user["senha"])
    autorizado = None
    if ok_senha:
        cur2 = conn.cursor()
        autorizado = _usuario_pro_valido(cur2, user["usuario"], dispositivo)
        if autorizado:
            cur2.execute("UPDATE usuarios SET ultimo_login = NOW() WHERE usuario = %s", (user["usuario"],))
            conn.commit()
        cur2.close()
    cur.close()
    conn.close()

    if not ok_senha:
        _registrar_falha_login(nome)
        return jsonify({"error": "E-mail ou senha inválidos. O login é o seu e-mail."}), 401
    _limpar_falhas_login(nome)
    if not autorizado:
        print(f"login MrDeskPro recusado: usuario {nome} a partir de {dispositivo} (nao autorizado)",
              file=sys.stderr, flush=True)
        return jsonify({"error": "Este MrDeskPro não está autorizado para este usuário."}), 401

    token = serializer_pro.dumps({"u": user["usuario"], "d": dispositivo})
    return jsonify({
        "type": "access_token",
        "access_token": token,
        "user": _payload_usuario_pro(user["nome"], user["admin"], user["email"]),
    })


@app.route("/api/currentUser", methods=["POST"])
def current_user_pro():
    sessao = _sessao_pro()
    if not sessao:
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    nome, admin, email = sessao[2]
    return jsonify(_payload_usuario_pro(nome, admin, email))


@app.route("/api/logout", methods=["POST"])
def logout_pro():
    return jsonify({})


def _conta_do_usuario(cur, usuario_id):
    # Conta = o admin da empresa: o proprio usuario se for admin de empresa,
    # senao o master dele. Superadmin nao tem conta (None).
    cur.execute(
        "SELECT CASE WHEN admin = 'S' THEN usuario ELSE master END FROM usuarios "
        "WHERE usuario = %s AND master IS NOT NULL",
        (usuario_id,)
    )
    r = cur.fetchone()
    return r[0] if r else None


def _fichas_pro(cur, conta):
    # Dispositivos ativos da conta, como o MrDeskPro mostra. Cliente nulo: o
    # card mostra so o apelido (vai no lugar do cliente e a direita fica vazio).
    cur.execute(
        "SELECT d.id, dc.cliente, dc.apelido, d.sistema, c.nome AS catalogo_nome "
        "FROM devices_contas dc JOIN devices d ON d.id = dc.dispositivo "
        "JOIN catalogos c ON c.conta = dc.conta AND c.catalogo = dc.catalogo "
        "WHERE dc.conta = %s AND dc.ativo = 'S' "
        "ORDER BY COALESCE(dc.cliente, dc.apelido), dc.apelido",
        (conta,)
    )
    fichas = []
    for id_, cliente, apelido, sistema, catalogo_nome in cur.fetchall():
        cliente = (cliente or "").strip()
        fichas.append({
            "id": id_,
            "esquerda": cliente or (apelido or ""),
            "direita": (apelido or "") if cliente else "",
            "sistema": sistema or "",
            "catalogo": (catalogo_nome or "").strip(),
            "cliente": cliente,
            "apelido": (apelido or "").strip(),
        })
    return fichas


# O que o MrDeskPro precisa ter igual ao servidor pra poder alterar uma ficha:
# cliente, apelido e nome do catalogo, como foram mandados pra ele.
def _versao_ficha_pro(cliente, apelido, catalogo_nome):
    return [(cliente or "").strip(), (apelido or "").strip(), (catalogo_nome or "").strip()]


@app.route("/api/ab", methods=["GET"])
def catalogo_pro():
    import json as _json
    sessao = _sessao_pro()
    if not sessao:
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401

    conn = get_db()
    cur = conn.cursor()
    conta = _conta_do_usuario(cur, sessao[0])
    fichas = _fichas_pro(cur, conta)
    # etiquetas = todos os catalogos da conta (inclusive os vazios, pra poder mover pra eles)
    cur.execute("SELECT nome FROM catalogos WHERE conta = %s ORDER BY catalogo", (conta,))
    tags = [(r[0] or "").strip() for r in cur.fetchall() if (r[0] or "").strip()]
    # este MrDeskPro esta com o catalogo em dia a partir de agora: guarda a copia
    # que ele passa a ter (versao_catalogo_local), pra saber depois o que ele alterou
    copia = {
        f["id"]: {
            "v": _versao_ficha_pro(f["cliente"], f["apelido"], f["catalogo"]),
            "a": "",
            "t": [f["catalogo"]] if f["catalogo"] else [],
        } for f in fichas
    }
    cur.execute(
        "UPDATE tecnicos_autorizados SET catalogo_lido = NOW(), versao_catalogo_local = %s "
        "WHERE dispositivo = %s",
        (psycopg2.extras.Json(copia), sessao[1])
    )
    conn.commit()
    cur.close()
    conn.close()

    peers = [{
        "id": f["id"],
        "username": f["esquerda"],   # 2a linha do card, a esquerda
        "hostname": f["direita"],    # 2a linha do card, a direita
        "alias": "",
        "platform": "Windows" if f["sistema"].lower().startswith("windows") else "",
        "tags": [f["catalogo"]] if f["catalogo"] else [],
    } for f in fichas]
    dados = {"tags": tags, "peers": peers, "tag_colors": "{}"}
    return jsonify({"data": _json.dumps(dados, ensure_ascii=False)})


# O MrDeskPro manda o catalogo INTEIRO de volta em varias situacoes: quando o
# tecnico renomeia um dispositivo ou troca a etiqueta, e tambem sozinho, a cada
# conexao com senha lembrada (manda o resumo da senha). Recusar com erro fazia
# aparecer "Nao foi possivel sincronizar o diretorio com o servidor" (02/10),
# entao o reenvio recebe resposta vazia = sucesso. So ha erro quando o tecnico
# alterou algo e a lista dele esta velha (04/10, ver abaixo).
# Item 41: duas edicoes valem (o modo simples do catalogo nao tem anotacao):
#   - renomear ("alias")  -> grava no apelido da ficha da conta
#   - trocar a etiqueta   -> move pro catalogo com aquele nome (da conta)
# Incluir, excluir e o resto do conteudo continuam ignorados.
# O MrDeskPro reenvia o catalogo inteiro sozinho, e a copia dele pode estar
# velha. Pra saber o que o tecnico alterou de verdade, o servidor guarda a
# copia que cada MrDeskPro tem (tecnicos_autorizados.versao_catalogo_local):
# por dispositivo, a ficha como foi mandada pra ele ("v": cliente, apelido,
# catalogo) e o nome/etiquetas que ele mandou por ultimo ("a", "t").
#   - nome ou etiquetas iguais aos da copia  -> so reenvio, ignora
#   - diferentes, e a ficha continua como ele recebeu -> grava
#   - diferentes, mas a ficha mudou no painel depois que ele leu -> recusa e
#     responde com erro (o MrDeskPro mostra a mensagem no lugar do "Sucesso")
MSG_CATALOGO_VELHO = ("A lista de dispositivos está desatualizada. "
                      "Atualize a lista e repita a alteração.")


@app.route("/api/ab", methods=["POST"])
def catalogo_pro_gravar():
    import json as _json
    sessao = _sessao_pro()
    if not sessao:
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    usuario_id, mrdeskpro, linha = sessao

    corpo = request.get_json(force=True, silent=True) or {}
    try:
        dados = corpo.get("data")
        dados = _json.loads(dados) if isinstance(dados, str) else dados
        peers = dados.get("peers") if isinstance(dados, dict) else None
    except (ValueError, AttributeError):
        peers = None
    if not isinstance(peers, list):
        return ("", 200)

    conn = get_db()
    cur = conn.cursor()
    recusou = False
    try:
        conta = _conta_do_usuario(cur, usuario_id)
        if conta is None:
            return ("", 200)
        cur.execute("SELECT versao_catalogo_local FROM tecnicos_autorizados WHERE dispositivo = %s FOR UPDATE",
                    (mrdeskpro,))
        r = cur.fetchone()
        if not r:
            return ("", 200)
        copia = r[0] if isinstance(r[0], dict) else {}

        cur.execute("SELECT nome, catalogo FROM catalogos WHERE conta = %s", (conta,))
        catalogos = {(nome or "").strip(): cat for nome, cat in cur.fetchall()}
        nomes_catalogos = {cat: nome for nome, cat in catalogos.items()}
        cur.execute(
            "SELECT dispositivo, cliente, apelido, catalogo FROM devices_contas "
            "WHERE conta = %s AND ativo = 'S'",
            (conta,)
        )
        fichas = {d: (cliente, apelido, cat) for d, cliente, apelido, cat in cur.fetchall()}

        mudou_copia = False
        for peer in peers[:5000]:
            if not isinstance(peer, dict):
                continue
            id_ = str(peer.get("id") or "")
            ficha = fichas.get(id_)
            if not ficha:
                continue  # nao e da conta
            cliente, apelido, catalogo = ficha
            versao_atual = _versao_ficha_pro(cliente, apelido, nomes_catalogos.get(catalogo, ""))
            item = copia.get(id_)
            if not isinstance(item, dict):
                item = None

            alias = str(peer.get("alias") or "").strip()[:100]
            tags = peer.get("tags")
            tags = [str(t).strip() for t in tags] if isinstance(tags, list) else None

            # sem copia desta ficha (MrDeskPro que ainda nao releu o catalogo, ou
            # ficha que entrou depois): compara com o que o servidor mandaria
            alias_antes = item.get("a", "") if item else ""
            tags_antes = item.get("t", []) if item else ([versao_atual[2]] if versao_atual[2] else [])

            mudou_nome = bool(alias) and alias != alias_antes
            mudou_tags = tags is not None and sorted(tags) != sorted(tags_antes)
            if not mudou_nome and not mudou_tags:
                continue  # so reenvio

            # A ficha continua como este MrDeskPro recebeu?
            if not item or item.get("v") != versao_atual:
                recusou = True
                continue

            novo_apelido = alias if mudou_nome else apelido
            novo_catalogo = catalogo
            if mudou_tags:
                # A tela de etiquetas deixa marcar varias: quando o tecnico marca
                # a nova sem desmarcar a antiga chegam as duas. Vale a que for
                # diferente do catalogo atual (o dispositivo so fica em um).
                outros = [catalogos[t] for t in tags if t in catalogos and catalogos[t] != catalogo]
                if outros:
                    novo_catalogo = outros[0]
            if novo_apelido != apelido or novo_catalogo != catalogo:
                cur.execute(
                    "UPDATE devices_contas SET apelido = %s, catalogo = %s, usuario = %s, atualizado = NOW() "
                    "WHERE dispositivo = %s AND conta = %s",
                    (novo_apelido, novo_catalogo, linha[0], id_, conta)
                )
            # a copia dele passa a ser o que ele mandou, sobre a ficha como ficou
            copia[id_] = {
                "v": _versao_ficha_pro(cliente, novo_apelido, nomes_catalogos.get(novo_catalogo, "")),
                "a": alias if mudou_nome else alias_antes,
                "t": tags if tags is not None else tags_antes,
            }
            mudou_copia = True
        if mudou_copia:
            cur.execute("UPDATE tecnicos_autorizados SET versao_catalogo_local = %s WHERE dispositivo = %s",
                        (psycopg2.extras.Json(copia), mrdeskpro))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    if recusou:
        # 200 com "error": o MrDeskPro mostra o texto no lugar do "Sucesso"
        return jsonify({"error": MSG_CATALOGO_VELHO})
    return ("", 200)


# Aba "Grupo" do MrDeskPro: depois do login ele pede grupos de dispositivos,
# usuarios e dispositivos acessiveis (recurso do servidor Pro do RustDesk).
# Sem estas rotas o MrDeskPro mostrava "Nao foi possivel atualizar o grupo:
# HTTP 404". Decisao do Celso (01/10): os catalogos aparecem como grupos de
# dispositivos; os dispositivos sao os mesmos do catalogo de enderecos (item
# 41: os ativos da conta do tecnico). Usuarios: vazio.
# Paginacao do RustDesk: ?current=N&pageSize=100 -> {"total", "data"}.
# Sem sessao valida: 401 (o MrDeskPro sai do login).
def _pagina_pro(itens):
    try:
        atual = max(int(request.args.get("current", 1)), 1)
        tamanho = min(max(int(request.args.get("pageSize", 100)), 1), 500)
    except (TypeError, ValueError):
        atual, tamanho = 1, 100
    inicio = (atual - 1) * tamanho
    return jsonify({"total": len(itens), "data": itens[inicio:inicio + tamanho]})


@app.route("/api/device-group/accessible", methods=["GET"])
def grupos_pro():
    sessao = _sessao_pro()
    if not sessao:
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT nome FROM catalogos WHERE conta = %s ORDER BY nome",
                (_conta_do_usuario(cur, sessao[0]),))
    grupos = [{"name": (r[0] or "").strip()} for r in cur.fetchall() if (r[0] or "").strip()]
    cur.close()
    conn.close()
    return _pagina_pro(grupos)


@app.route("/api/users", methods=["GET"])
def usuarios_pro():
    if not _sessao_pro():
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    return jsonify({"total": 0, "data": []})


@app.route("/api/peers", methods=["GET"])
def dispositivos_pro():
    sessao = _sessao_pro()
    if not sessao:
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    conn = get_db()
    cur = conn.cursor()
    fichas = _fichas_pro(cur, _conta_do_usuario(cur, sessao[0]))
    cur.close()
    conn.close()
    itens = [{
        "id": f["id"],
        # card: cliente a esquerda (username) e apelido a direita (device_name)
        "info": {"username": f["esquerda"], "device_name": f["direita"], "os": f["sistema"]},
        "status": 1,
        "user": "",
        "user_name": "",
        "device_group_name": f["catalogo"],
        "note": "",
    } for f in fichas]
    return _pagina_pro(itens)


# ------------------------------------------------------------
# AUDITORIA de conexoes (RustDesk /api/audit/conn)
# ------------------------------------------------------------
# O client manda ate 3 POSTs por acesso remoto:
#   1) abertura:  {"action": "new", "ip": "..."} - antes do login
#   2) login ok:  {"peer": [id, nome], "type": N}  - sem campo "action"
#   3) fechamento:{"action": "close"}
# Em todos, o client tambem inclui: id (dispositivo controlado), uuid,
# conn_id, session_id, nonce. Guardamos 1 linha por acesso (nao por
# evento), com chave natural (dispositivo, acesso) - item 13.
#
# acesso (BIGINT) = segundo em que o servico do MrDesk iniciou (10 digitos)
# * 1.000.000 + conn_id (6 digitos). O conn_id sozinho recomeca do 1 quando o
# servico reinicia, por isso nao serve de chave.
#   - MrDesk 1.4.10+ (patch 13 do rdgen) manda o numero pronto em
#     "mrdesk_acesso", igual nos 3 avisos: junta direto pela chave.
#   - MrDesk antigo (sem "mrdesk_acesso"): o servidor gera o numero na
#     ABERTURA (hora da chegada * 1.000.000 + conn_id) e sempre cria linha
#     nova. Login e fechamento completam a linha mais recente ainda aberta
#     (fim vazio) desse dispositivo com o mesmo conn_id (6 ultimos digitos).
#     Abertura reenviada (mesmo conn_id e mesma sessao, ainda aberta) reusa
#     a linha em vez de duplicar.
#
# Importante: pelo codigo-fonte do RustDesk, o client so considera a
# postagem bem-sucedida se a resposta vier com corpo VAZIO (HTTP 200).
# Qualquer corpo nao-vazio - inclusive um "{}" - e tratado como possivel
# falha e o client reenvia o mesmo evento. Por isso aqui NAO usamos
# jsonify({}), retornamos uma resposta realmente vazia.
ACESSO_FATOR = 1000000

# Campos que cada evento completa na linha (COALESCE: so sobrescreve com valor).
_AUDIT_SET = """
    sessao    = COALESCE(%(sessao)s, auditoria.sessao),
    ip        = COALESCE(%(ip)s::inet, auditoria.ip),
    origem    = COALESCE(%(origem)s, auditoria.origem),
    nome      = COALESCE(%(nome)s, auditoria.nome),
    tipo      = COALESCE(%(tipo)s, auditoria.tipo),
    uuid      = COALESCE(%(uuid)s, auditoria.uuid),
    fim       = CASE WHEN %(fecha)s THEN NOW()      -- fechamento real vale mais que o automatico
                     WHEN %(login)s THEN NULL       -- login reabre a linha (item 34)
                     ELSE auditoria.fim END,
    autenticacao = COALESCE(%(autenticacao)s, auditoria.autenticacao),
    permissao = COALESCE(%(permissao)s, auditoria.permissao),
    conta     = COALESCE(%(conta)s, auditoria.conta)
"""

_AUDIT_INSERT = """
    INSERT INTO auditoria (dispositivo, acesso, sessao, ip, origem, nome, tipo, uuid, inicio, fim, permissao,
                           autenticacao, conta)
    VALUES (%(dispositivo)s, {acesso}, %(sessao)s, %(ip)s, %(origem)s, %(nome)s, %(tipo)s, %(uuid)s,
            NOW(), CASE WHEN %(fecha)s THEN NOW() ELSE NULL END, COALESCE(%(permissao)s, 'P'),
            %(autenticacao)s, %(conta)s)
"""


@app.route("/api/audit/conn", methods=["POST"])
def audit_conn():
    data = request.get_json(force=True, silent=True) or {}

    dispositivo = data.get("id")
    conexao = data.get("conn_id")
    sessao = data.get("session_id")
    if not dispositivo or conexao is None or sessao is None:
        return ("", 200)

    try:
        conexao = int(conexao) % ACESSO_FATOR
    except (TypeError, ValueError):
        return ("", 200)

    # Numero do acesso mandado pelo MrDesk 1.4.10+ (patch 13). Antigos nao mandam.
    acesso = data.get("mrdesk_acesso")
    try:
        acesso = int(acesso) if acesso is not None else None
    except (TypeError, ValueError):
        acesso = None
    if acesso is not None and acesso <= 0:
        acesso = None

    action = data.get("action")
    # Controle de acesso (item 6A): o MrDesk com o patch manda "permissao"
    # (P = permitida, B = bloqueada, F = falha na verificacao). Clientes sem o
    # patch nao mandam: fica o default da coluna ('P' - nao havia controle).
    permissao = data.get("permissao")
    if permissao not in ("P", "B", "F"):
        permissao = None

    origem = None
    nome = None
    tipo = None
    if not action:
        # Sem "action" = evento de login: vem com "peer" (quem conectou) e "type".
        peer = data.get("peer")
        if isinstance(peer, list):
            origem = peer[0] if len(peer) > 0 else None
            nome = peer[1] if len(peer) > 1 else None
        tipo = data.get("type")

    # Item 33: como o acesso foi autorizado (o MrDesk manda "primary_auth" no
    # aviso de login): 1 aceite na tela, 2 senha temporaria, 3 senha permanente,
    # 4 troca de lado.
    autenticacao = data.get("primary_auth")
    if autenticacao not in (1, 2, 3, 4):
        autenticacao = None

    p = {
        "dispositivo": str(dispositivo)[:20],
        "acesso": acesso,
        "conexao": conexao,
        "fator": ACESSO_FATOR,
        "sessao": str(sessao),
        "ip": data.get("ip") if action == "new" else None,
        "origem": str(origem)[:20] if origem is not None else None,
        "nome": nome,
        "tipo": tipo,
        "uuid": _uuid_recebido(data),
        "fecha": action == "close",
        "login": not action,
        "permissao": permissao,
        "autenticacao": autenticacao,
        "conta": None,
    }

    conn = get_db()
    cur = conn.cursor()
    try:
        # Item 9: so grava aviso da maquina registrada pra esse ID.
        if not _maquina_confere(cur, p["dispositivo"], p["uuid"], "auditoria"):
            conn.commit()
            return ("", 200)

        # Item 41: no aviso de login, a conta do tecnico (dono do MrDeskPro que
        # conectou) fica gravada no acesso. E, se o acesso foi permitido, o
        # dispositivo entra na conta - e assim que a ligacao nasce (primeiro
        # acesso que deu certo): apelido = nome do computador, sem cliente, no
        # catalogo "Novos" da conta. Quem ja esta ligado nao muda.
        if p["login"] and p["origem"]:
            cur.execute(
                "SELECT CASE WHEN u.admin = 'S' THEN u.usuario ELSE u.master END "
                "FROM tecnicos_autorizados t JOIN usuarios u ON u.usuario = t.usuario "
                "WHERE t.dispositivo = %s AND u.master IS NOT NULL",
                (p["origem"],)
            )
            r = cur.fetchone()
            p["conta"] = r[0] if r else None
            if p["conta"] is not None and permissao in (None, "P"):
                cur.execute(
                    "INSERT INTO devices_contas (dispositivo, conta, apelido, usuario, catalogo) "
                    "SELECT d.id, %(conta)s, COALESCE(NULLIF(TRIM(d.computador), ''), d.id), 'sistema', "
                    "       %(novos)s "
                    "FROM devices d WHERE d.id = %(dispositivo)s "
                    "AND EXISTS (SELECT 1 FROM catalogos WHERE conta = %(conta)s AND catalogo = %(novos)s) "
                    "ON CONFLICT (dispositivo, conta) DO NOTHING",
                    dict(p, novos=CATALOGO_NOVOS)
                )
        if acesso is not None:
            # MrDesk 1.4.10+: o numero ja identifica o acesso.
            cur.execute(
                _AUDIT_INSERT.format(acesso="%(acesso)s")
                + " ON CONFLICT (dispositivo, acesso) DO UPDATE SET " + _AUDIT_SET
                + " WHERE auditoria.uuid IS NULL OR auditoria.uuid = %(uuid)s",
                p
            )
        elif action == "new":
            # MrDesk antigo, abertura: reenvio da mesma abertura reusa a linha.
            cur.execute(
                "SELECT acesso FROM auditoria WHERE dispositivo = %(dispositivo)s "
                "AND acesso %% %(fator)s = %(conexao)s AND sessao = %(sessao)s AND fim IS NULL "
                "AND (uuid IS NULL OR uuid = %(uuid)s) "
                "ORDER BY acesso DESC LIMIT 1",
                p
            )
            row = cur.fetchone()
            if row:
                p["acesso"] = row[0]
                cur.execute(
                    "UPDATE auditoria SET " + _AUDIT_SET
                    + " WHERE dispositivo = %(dispositivo)s AND acesso = %(acesso)s",
                    p
                )
            else:
                cur.execute(
                    _AUDIT_INSERT.format(
                        acesso="TRUNC(EXTRACT(EPOCH FROM NOW()))::BIGINT * %(fator)s + %(conexao)s")
                    + " ON CONFLICT (dispositivo, acesso) DO NOTHING",
                    p
                )
        else:
            # MrDesk antigo, login/fechamento: completa a linha aberta mais recente.
            cur.execute(
                "SELECT acesso FROM auditoria WHERE dispositivo = %(dispositivo)s "
                "AND acesso %% %(fator)s = %(conexao)s AND fim IS NULL "
                "AND (uuid IS NULL OR uuid = %(uuid)s) "
                "ORDER BY acesso DESC LIMIT 1",
                p
            )
            row = cur.fetchone()
            if row:
                p["acesso"] = row[0]
                cur.execute(
                    "UPDATE auditoria SET " + _AUDIT_SET
                    + " WHERE dispositivo = %(dispositivo)s AND acesso = %(acesso)s",
                    p
                )
            elif not p["fecha"]:
                # Login sem abertura registrada (aviso de abertura perdido): cria a linha.
                cur.execute(
                    _AUDIT_INSERT.format(
                        acesso="TRUNC(EXTRACT(EPOCH FROM NOW()))::BIGINT * %(fator)s + %(conexao)s")
                    + " ON CONFLICT (dispositivo, acesso) DO NOTHING",
                    p
                )
            # Fechamento sem linha aberta = reenvio de um fechamento ja gravado: ignora.
        conn.commit()
    except psycopg2.errors.ForeignKeyViolation:
        # fk_auditoria_device: o dispositivo nao existe em devices (quase
        # impossivel - o heartbeat cria o device assim que o servico inicia).
        # Fica sem auditoria, mas registra no log do servico
        # (journalctl -u mrdesk-suporte). A resposta continua vazia/200,
        # senao o client reenvia o mesmo evento sem parar.
        conn.rollback()
        print(f"auditoria ignorada: dispositivo {dispositivo} nao existe em devices "
              f"(conexao {conexao})", file=sys.stderr, flush=True)
    finally:
        cur.close()
        conn.close()

    return ("", 200)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050)
