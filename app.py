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


def gerar_token(username, admin=False, excluir_device=False):
    return serializer.dumps({
        "username": username,
        "admin": admin,
        "excluir_device": excluir_device
    })


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"success": False, "error": "Login necessario"}), 401
        try:
            data = serializer.loads(token, max_age=TOKEN_MAX_AGE)
            request.usuario_logado = data["username"]
            request.usuario_admin = data.get("admin", False)
            request.usuario_excluir_device = data.get("excluir_device", False)
        except SignatureExpired:
            return jsonify({"success": False, "error": "Sessao expirada, faca login novamente"}), 401
        except BadSignature:
            return jsonify({"success": False, "error": "Token invalido"}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(request, "usuario_admin", False):
            return jsonify({"success": False, "error": "Acesso restrito a administradores"}), 403
        return f(*args, **kwargs)
    return decorated


def require_excluir_device(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        pode = getattr(request, "usuario_admin", False) or getattr(request, "usuario_excluir_device", False)
        if not pode:
            return jsonify({"success": False, "error": "Sem permissao para excluir dispositivos"}), 403
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
# LOGIN
# ------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "error": "Usuario e senha obrigatorios"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM usuarios WHERE nome = %s AND ativo = 'S'", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not bcrypt.checkpw(password.encode(), user["senha"].encode()):
        return jsonify({"success": False, "error": "Usuario ou senha invalidos"}), 401

    admin = user["admin"] == "S"
    excluir_device = user["excluir_device"] == "S"

    return jsonify({
        "success": True,
        "name": user["nome"],
        "admin": admin,
        "excluir_device": excluir_device,
        "token": gerar_token(user["nome"], admin=admin, excluir_device=excluir_device)
    })


# ------------------------------------------------------------
# ALTERAR A PROPRIA SENHA - qualquer usuario logado
# ------------------------------------------------------------
@app.route("/api/usuarios/senha", methods=["PUT"])
@require_auth
def alterar_propria_senha():
    data = request.get_json()
    senha_atual = data.get("senha_atual") or ""
    nova_senha = data.get("nova_senha") or ""

    if not senha_atual or not nova_senha:
        return jsonify({"success": False, "error": "Senha atual e nova senha sao obrigatorias"}), 400

    if len(nova_senha) < 6:
        return jsonify({"success": False, "error": "A nova senha deve ter pelo menos 6 caracteres"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM usuarios WHERE nome = %s", (request.usuario_logado,))
    user = cur.fetchone()

    if not user or not bcrypt.checkpw(senha_atual.encode(), user["senha"].encode()):
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Senha atual incorreta"}), 401

    nova_senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()
    cur.close()

    cur = conn.cursor()
    cur.execute(
        "UPDATE usuarios SET senha=%s, alterado=NOW() WHERE usuario=%s",
        (nova_senha_hash, user["usuario"])
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"success": True})


# ------------------------------------------------------------
# USUARIOS (Item 18) - somente admin gerencia
# ------------------------------------------------------------
@app.route("/api/usuarios", methods=["GET"])
@require_auth
@require_admin
def list_usuarios():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT usuario, nome, email, excluir_device, observacoes, admin, ativo, inclusao, alterado "
        "FROM usuarios ORDER BY nome"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    usuarios = []
    for r in rows:
        usuarios.append({
            "usuario": r["usuario"],
            "nome": r["nome"],
            "email": r["email"],
            "excluir_device": r["excluir_device"],
            "observacoes": r["observacoes"],
            "admin": r["admin"],
            "ativo": r["ativo"],
            "inclusao": r["inclusao"].isoformat() if r["inclusao"] else None,
            "alterado": r["alterado"].isoformat() if r["alterado"] else None
        })

    return jsonify({"success": True, "usuarios": usuarios})


@app.route("/api/usuarios", methods=["POST"])
@require_auth
@require_admin
def add_usuario():
    data = request.get_json()
    nome = (data.get("nome") or "").strip()
    senha = data.get("senha") or ""
    email = data.get("email")
    excluir_device = data.get("excluir_device", "N")
    observacoes = data.get("observacoes")
    ativo = data.get("ativo", "S")

    # Usuarios criados por essa tela nunca sao admin: so existe um admin
    # (o cadastro original), e essa tela nao oferece meio de alterar isso.
    admin = "N"

    if excluir_device not in ("S", "N"):
        excluir_device = "N"
    if ativo not in ("S", "N"):
        ativo = "S"

    if not nome or not senha:
        return jsonify({"success": False, "error": "nome e senha sao obrigatorios"}), 400

    senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO usuarios (nome, senha, email, excluir_device, observacoes, admin, ativo) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (nome, senha_hash, email, excluir_device, observacoes, admin, ativo)
        )
        conn.commit()
        return jsonify({"success": True})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"success": False, "error": "Ja existe um usuario com esse nome"}), 409
    finally:
        cur.close()
        conn.close()


@app.route("/api/usuarios/<int:usuario_id>", methods=["PUT"])
@require_auth
@require_admin
def edit_usuario(usuario_id):
    data = request.get_json()
    email = data.get("email")
    excluir_device = data.get("excluir_device", "N")
    observacoes = data.get("observacoes")
    ativo = data.get("ativo", "S")
    nova_senha = data.get("senha")  # opcional: so muda se vier preenchida

    if excluir_device not in ("S", "N"):
        excluir_device = "N"
    if ativo not in ("S", "N"):
        ativo = "S"

    # O campo "admin" nao e alterado por essa tela (proposital: so existe
    # um admin). Por isso ele fica de fora do UPDATE, preservando o valor
    # atual no banco mesmo quando o proprio admin edita seu cadastro.
    conn = get_db()
    cur = conn.cursor()

    if nova_senha:
        senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "UPDATE usuarios SET email=%s, excluir_device=%s, observacoes=%s, "
            "ativo=%s, senha=%s, alterado=NOW() WHERE usuario=%s",
            (email, excluir_device, observacoes, ativo, senha_hash, usuario_id)
        )
    else:
        cur.execute(
            "UPDATE usuarios SET email=%s, excluir_device=%s, observacoes=%s, "
            "ativo=%s, alterado=NOW() WHERE usuario=%s",
            (email, excluir_device, observacoes, ativo, usuario_id)
        )

    conn.commit()
    updated = cur.rowcount
    cur.close()
    conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Usuario nao encontrado"}), 404

    return jsonify({"success": True})


@app.route("/api/usuarios/<int:usuario_id>", methods=["DELETE"])
@require_auth
@require_admin
def delete_usuario(usuario_id):
    conn = get_db()
    cur = conn.cursor()

    # Nunca permite excluir o usuario admin, seja qual for o ID dele.
    cur.execute("SELECT admin FROM usuarios WHERE usuario = %s", (usuario_id,))
    row = cur.fetchone()
    if row and row[0] == "S":
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Nao e permitido excluir o usuario administrador"}), 403

    try:
        cur.execute("DELETE FROM usuarios WHERE usuario = %s AND admin <> 'S'", (usuario_id,))
        conn.commit()
    except psycopg2.errors.ForeignKeyViolation:
        # fk_tecnico_usuario: o usuario tem MrDeskPro em "Tecnicos autorizados".
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Usuário com MrDeskPro cadastrado em Técnicos autorizados não pode ser excluído; desative-o."}), 409
    deleted = cur.rowcount
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({"success": False, "error": "Usuario nao encontrado"}), 404

    return jsonify({"success": True})


# ------------------------------------------------------------
# CATALOGOS
# ------------------------------------------------------------
TAMANHO_NOME_CATALOGO = 10  # catalogos.nome e varchar(10)

@app.route("/api/catalogos", methods=["GET"])
@require_auth
def list_catalogos():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT catalogo, nome, senha_geral FROM catalogos ORDER BY catalogo")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    catalogos = []
    for r in rows:
        catalogos.append({
            "catalogo": int(r["catalogo"]),
            "nome": r["nome"],
            "senha_geral": "S" if r["senha_geral"] == "S" else "N",
        })
    return jsonify({"success": True, "catalogos": catalogos})


@app.route("/api/catalogos", methods=["POST"])
@require_auth
def add_catalogo():
    data = request.get_json()
    nome = (data.get("nome") or "").strip()
    if not nome:
        return jsonify({"success": False, "error": "Nome obrigatorio"}), 400
    if len(nome) > TAMANHO_NOME_CATALOGO:
        return jsonify({"success": False, "error": f"O nome do catálogo tem no máximo {TAMANHO_NOME_CATALOGO} caracteres"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(MAX(catalogo), 0) + 1 FROM catalogos")
    novo_id = cur.fetchone()[0]
    cur.execute("INSERT INTO catalogos (catalogo, nome) VALUES (%s, %s)", (novo_id, nome))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"success": True, "catalogo": novo_id, "nome": nome})


# EDITAR catalogo - so o admin. "senha_geral" = 'S' libera, nos dispositivos
# desse catalogo, a senha geral do tecnico (item 6B, ainda nao implementado:
# por enquanto o campo so fica gravado). Qualquer valor diferente de 'S' = nao.
@app.route("/api/catalogos/<int:catalogo_id>", methods=["PUT"])
@require_auth
@require_admin
def edit_catalogo(catalogo_id):
    data = request.get_json() or {}
    nome = (data.get("nome") or "").strip()
    senha_geral = "S" if data.get("senha_geral") == "S" else "N"
    if not nome:
        return jsonify({"success": False, "error": "Nome obrigatorio"}), 400
    if len(nome) > TAMANHO_NOME_CATALOGO:
        return jsonify({"success": False, "error": f"O nome do catálogo tem no máximo {TAMANHO_NOME_CATALOGO} caracteres"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE catalogos SET nome=%s, senha_geral=%s WHERE catalogo=%s",
        (nome, senha_geral, catalogo_id)
    )
    conn.commit()
    updated = cur.rowcount
    cur.close()
    conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Catalogo nao encontrado"}), 404
    return jsonify({"success": True})


# ------------------------------------------------------------
# LISTAR dispositivos
# ------------------------------------------------------------
@app.route("/api/devices", methods=["GET"])
@require_auth
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

    if not catalogo:
        return jsonify({"success": False, "error": "catalogo e obrigatorio"}), 400

    condicoes = ["catalogo = %s", "ativo = %s", "servidor = %s", "instalado = %s"]
    parametros = [catalogo, filtro_ativo, filtro_servidor, filtro_instalado]

    where_sql = " AND ".join(condicoes)

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        f"SELECT id, cliente, apelido, observacao, usuario, ativo, servidor, catalogo, "
        f"ultima_vez_online, inclusao, atualizado, "
        # tempo sem sinal calculado DENTRO do banco (mesmo relogio que gravou
        # ultima_vez_online) - nao depende do relogio/fuso do Python
        f"EXTRACT(EPOCH FROM (NOW() - ultima_vez_online)) AS segundos_sem_sinal, "
        f"EXTRACT(EPOCH FROM (NOW() - ultima_atividade)) AS segundos_sem_uso "
        f"FROM devices WHERE {where_sql} ORDER BY cliente, apelido",
        parametros
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
# PEGAR link de conexao
# ------------------------------------------------------------
# Os links de conexao abrem o app do TECNICO (MrDeskPro). O RustDesk registra
# no Windows um protocolo com o nome do app em minusculas, entao o MrDeskPro
# responde a "mrdeskpro://" (o "mrdesk://" e do app dos clientes, que so
# recebe conexao).
ESQUEMA_CONEXAO = "mrdeskpro"


@app.route("/api/devices/<device_id>/connect", methods=["GET"])
@require_auth
def get_connect_link(device_id):
    modo = request.args.get("mode", "connect")
    modos_validos = ["connect", "file-transfer", "view-camera", "terminal", "port-forward"]
    if modo not in modos_validos:
        modo = "connect"

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        link = f"{ESQUEMA_CONEXAO}://{modo}/{row['id']}"
        return jsonify({"success": True, "link": link})

    # ID ainda nao cadastrado: permite conectar mesmo assim (botao "Acessar"
    # da busca), desde que tenha o formato de um ID do MrDesk (9 ou 10
    # digitos). Na primeira conexao o proprio client se cadastra pelo heartbeat.
    if device_id.isdigit() and 9 <= len(device_id) <= 10:
        return jsonify({"success": True, "link": f"{ESQUEMA_CONEXAO}://{modo}/{device_id}"})

    return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404


# ------------------------------------------------------------
# SESSOES VIA RELAY (hbbr) nos ultimos 30 dias
# ------------------------------------------------------------
# A tabela relay_sessoes e preenchida pelo coletar_relay.py (timer do
# systemd, a cada 5 min). Aqui so contamos: sessoes que passaram pelo relay
# x total de conexoes registradas na auditoria no mesmo periodo.
@app.route("/api/relay", methods=["GET"])
@require_auth
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
# LOCALIZAR um ID em qualquer catalogo, ignorando os filtros da tela
# ------------------------------------------------------------
# Usado pelo botao "Acessar" da busca: quando o ID digitado nao aparece na
# lista (por causa do catalogo ou dos filtros Ativo/Instalado/Servidor), a
# tela pergunta aqui onde ele esta, pra explicar no hint o que o esconde.
@app.route("/api/devices/localizar", methods=["GET"])
@require_auth
def localizar_device():
    device_id = (request.args.get("id") or "").strip()
    if not device_id.isdigit():
        return jsonify({"success": False, "error": "ID invalido"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT d.id, d.cliente, d.apelido, d.ativo, d.servidor, d.instalado, "
        "d.catalogo, c.nome AS catalogo_nome "
        "FROM devices d LEFT JOIN catalogos c ON c.catalogo = d.catalogo "
        "WHERE d.id = %s",
        (device_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"success": True, "encontrado": False})

    return jsonify({"success": True, "encontrado": True, "device": dict(row)})


# ------------------------------------------------------------
# HISTORICO de auditoria de conexoes de um dispositivo
# ------------------------------------------------------------
TIPOS_ACESSO_AUDITORIA = {
    0: "Remoto",
    1: "Transferencia de arquivo",
    2: "Port forward",
    3: "Ver camera",
    4: "Terminal",
}


@app.route("/api/devices/<device_id>/auditoria", methods=["GET"])
@require_auth
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
    cur.execute(
        "SELECT sequencia, inicio, fim, nome, origem, tipo, ip, permissao "
        "FROM auditoria WHERE dispositivo = %s AND inicio >= %s AND inicio < %s "
        "ORDER BY inicio DESC",
        (device_id, data_inicio, data_fim)
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
            "sequencia": row["sequencia"],
            "inicio": row["inicio"].isoformat() if row["inicio"] else None,
            "fim": row["fim"].isoformat() if row["fim"] else None,
            "duracao_segundos": duracao_segundos,
            "nome": row["nome"],
            "origem": row["origem"],
            "permissao": row["permissao"],
            "tipo": TIPOS_ACESSO_AUDITORIA.get(row["tipo"], "Desconhecido") if row["tipo"] is not None else None,
            "ip": row["ip"],
        })

    return jsonify({"success": True, "registros": registros})


# ------------------------------------------------------------
# ADICIONAR dispositivo
# ------------------------------------------------------------
@app.route("/api/devices", methods=["POST"])
@require_auth
def add_device():
    data = request.get_json()
    device_id = data.get("id")
    cliente = data.get("cliente")
    apelido = data.get("apelido")
    observacao = data.get("observacao", "")
    servidor = data.get("servidor", "N")
    catalogo = data.get("catalogo", 1)
    usuario = request.usuario_logado

    if servidor not in ("S", "N"):
        servidor = "N"

    if not all([device_id, cliente, apelido]):
        return jsonify({"success": False, "error": "id, cliente e apelido sao obrigatorios"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO devices (id, cliente, apelido, observacao, usuario, servidor, catalogo) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (device_id, cliente, apelido, observacao, usuario, servidor, catalogo)
        )
        conn.commit()
        return jsonify({"success": True})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"success": False, "error": "Ja existe um dispositivo com esse ID"}), 409
    finally:
        cur.close()
        conn.close()


# ------------------------------------------------------------
# EDITAR dispositivo
# ------------------------------------------------------------
@app.route("/api/devices/<device_id>", methods=["PUT"])
@require_auth
def edit_device(device_id):
    data = request.get_json()
    cliente = data.get("cliente")
    apelido = data.get("apelido")
    observacao = data.get("observacao", "")
    ativo = data.get("ativo", "S")
    servidor = data.get("servidor", "N")
    if ativo not in ("S", "N"):
        ativo = "S"
    if servidor not in ("S", "N"):
        servidor = "N"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE devices SET cliente=%s, apelido=%s, observacao=%s, ativo=%s, servidor=%s, atualizado=NOW() WHERE id=%s",
        (cliente, apelido, observacao, ativo, servidor, device_id)
    )
    conn.commit()
    updated = cur.rowcount
    cur.close()
    conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404

    return jsonify({"success": True})


# ------------------------------------------------------------
# MOVER dispositivo de catalogo
# ------------------------------------------------------------
@app.route("/api/devices/<device_id>/catalogo", methods=["PUT"])
@require_auth
def mover_catalogo(device_id):
    data = request.get_json()
    novo_catalogo = data.get("catalogo")
    if not novo_catalogo:
        return jsonify({"success": False, "error": "catalogo e obrigatorio"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE devices SET catalogo=%s, atualizado=NOW() WHERE id=%s",
        (novo_catalogo, device_id)
    )
    conn.commit()
    updated = cur.rowcount
    cur.close()
    conn.close()

    if updated == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404

    return jsonify({"success": True})


# ------------------------------------------------------------
# EXCLUIR dispositivo
# ------------------------------------------------------------
@app.route("/api/devices/<device_id>", methods=["DELETE"])
@require_auth
@require_excluir_device
def delete_device(device_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM devices WHERE id = %s", (device_id,))
        conn.commit()
    except psycopg2.errors.ForeignKeyViolation as e:
        # fk_auditoria_device (tem historico) ou fk_tecnico_device (e o
        # MrDeskPro de um tecnico). Excluir apagaria/"orfanaria" o historico e,
        # se o heartbeat recriasse o device com o mesmo ID, ele herdaria o
        # historico antigo. Por isso: desativar em vez de excluir.
        conn.rollback()
        cur.close()
        conn.close()
        if e.diag.constraint_name == "fk_tecnico_device":
            erro = "Dispositivo cadastrado em Técnicos autorizados não pode ser excluído; desative-o."
        else:
            erro = "Dispositivo com histórico de conexões não pode ser excluído; desative-o."
        return jsonify({"success": False, "error": erro}), 409
    deleted = cur.rowcount
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({"success": False, "error": "Dispositivo nao encontrado"}), 404

    return jsonify({"success": True})


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

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM devices WHERE id = %s", (device_id,))
    if cur.fetchone():
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
        cur.execute(
            "INSERT INTO devices (id, cliente, apelido, usuario, catalogo, ultima_vez_online) "
            "VALUES (%s, %s, %s, %s, %s, NOW()) ON CONFLICT (id) DO NOTHING",
            (device_id, "A definir", device_id, "sistema", 1)
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

    hostname = data.get("hostname") or device_id
    sistema = data.get("os", "")

    # Campo novo do client (patch aplicado em 26/09/2026): informa se o
    # RustDesk esta rodando instalado ("S") ou portatil/nao instalado ("N").
    # Clients antigos (sem o patch) nao mandam esse campo - nesse caso
    # nao mexemos na coluna, que ja tem DEFAULT 'S'.
    instalado = data.get("installed")
    if instalado not in ("S", "N"):
        instalado = None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, apelido FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()

    if row:
        # Ja existe: nao mexe em apelido/cliente (o tecnico pode ja
        # ter personalizado), so atualiza a observacao com o SO e
        # marca que esta vivo agora. instalado so e sobrescrito quando o
        # client manda o campo (CASE mantem o valor atual quando vier NULL) -
        # um unico UPDATE, priorizando performance (1 round-trip em vez de 2).
        cur.execute(
            "UPDATE devices SET observacao = %s, ultima_vez_online = NOW(), "
            "instalado = CASE WHEN %s IS NOT NULL THEN %s ELSE instalado END "
            "WHERE id = %s",
            (sistema, instalado, instalado, device_id)
        )
    else:
        cur.execute(
            "INSERT INTO devices (id, cliente, apelido, observacao, usuario, catalogo, ultima_vez_online, instalado) "
            "VALUES (%s, %s, %s, %s, %s, %s, NOW(), COALESCE(%s, 'S')) ON CONFLICT (id) DO NOTHING",
            (device_id, "A definir", hostname, sistema, "sistema", 1, instalado)
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


@app.route("/api/tecnicos", methods=["GET"])
@require_auth
@require_admin
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
        "ORDER BY u.nome, t.dispositivo"
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
@require_admin
def add_tecnico():
    dados, erro = _dados_tecnico(request.get_json() or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400

    conn = get_db()
    cur = conn.cursor()
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
@require_admin
def edit_tecnico(dispositivo_original):
    dados, erro = _dados_tecnico(request.get_json() or {})
    if erro:
        return jsonify({"success": False, "error": erro}), 400
    dispositivo, usuario, descricao, ativo = dados

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE tecnicos_autorizados SET dispositivo=%s, usuario=%s, descricao=%s, "
            "ativo=%s, alterado=NOW() WHERE dispositivo=%s",
            (dispositivo, usuario, descricao, ativo, _normalizar_id(dispositivo_original))
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
LIMITE_VERIFICACOES_POR_MINUTO = 60
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
    cur.execute(
        "SELECT 1 FROM tecnicos_autorizados t JOIN usuarios u ON u.usuario = t.usuario "
        "WHERE t.dispositivo = %s AND t.ativo = 'S' AND u.ativo = 'S'",
        (peer,)
    )
    autorizado = cur.fetchone() is not None
    cur.close()
    conn.close()
    return jsonify({"autorizado": autorizado})


# ------------------------------------------------------------
# AUDITORIA de conexoes (RustDesk /api/audit/conn)
# ------------------------------------------------------------
# O client manda ate 3 POSTs por sessao de conexao remota:
#   1) abertura:  {"action": "new", "ip": "..."} - antes do login
#   2) login ok:  {"peer": [id, nome], "type": N}  - sem campo "action"
#   3) fechamento:{"action": "close"}
# Em todos, o client tambem inclui: id (dispositivo controlado), uuid,
# conn_id, session_id, nonce. Guardamos 1 linha por sessao (nao por
# evento), correlacionada pela chave natural (dispositivo, conexao) -
# NAO inclui sessao: o session_id ainda nao tem o valor definitivo no
# evento de abertura (que acontece antes do login), entao o mesmo
# conn_id chega com um session_id diferente depois do login. conexao
# (conn_id) e o unico campo estavel durante toda a conexao. Vamos
# completando os demais campos conforme os eventos chegam.
#
# Importante: pelo codigo-fonte do RustDesk, o client so considera a
# postagem bem-sucedida se a resposta vier com corpo VAZIO (HTTP 200).
# Qualquer corpo nao-vazio - inclusive um "{}" - e tratado como possivel
# falha e o client reenvia o mesmo evento. Por isso aqui NAO usamos
# jsonify({}), retornamos uma resposta realmente vazia.
@app.route("/api/audit/conn", methods=["POST"])
def audit_conn():
    data = request.get_json(force=True, silent=True) or {}

    dispositivo = data.get("id")
    conexao = data.get("conn_id")
    sessao = data.get("session_id")
    if not dispositivo or conexao is None or sessao is None:
        return ("", 200)

    try:
        conexao = int(conexao)
    except (TypeError, ValueError):
        return ("", 200)

    action = data.get("action")
    ip = data.get("ip") if action == "new" else None
    uuid_val = data.get("uuid")
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

    is_close = (action == "close")

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO auditoria (dispositivo, conexao, sessao, ip, origem, nome, tipo, uuid, inicio, fim, permissao)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), CASE WHEN %s THEN NOW() ELSE NULL END, COALESCE(%s, 'P'))
            ON CONFLICT (dispositivo, conexao) DO UPDATE SET
                sessao    = COALESCE(EXCLUDED.sessao, auditoria.sessao),
                ip        = COALESCE(EXCLUDED.ip, auditoria.ip),
                origem    = COALESCE(EXCLUDED.origem, auditoria.origem),
                nome      = COALESCE(EXCLUDED.nome, auditoria.nome),
                tipo      = COALESCE(EXCLUDED.tipo, auditoria.tipo),
                uuid      = COALESCE(EXCLUDED.uuid, auditoria.uuid),
                fim       = COALESCE(EXCLUDED.fim, auditoria.fim),
                permissao = COALESCE(%s, auditoria.permissao)
            """,
            (str(dispositivo)[:20], conexao, str(sessao), ip,
             str(origem)[:20] if origem is not None else None,
             nome, tipo, uuid_val, is_close, permissao, permissao)
        )
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
