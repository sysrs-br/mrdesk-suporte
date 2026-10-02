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
    data = request.get_json(force=True, silent=True) or {}
    # Mesmo endereco do login do MrDeskPro (item 24): o RustDesk manda id/uuid.
    if data.get("uuid") and data.get("id"):
        return login_pro()
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

    condicoes = ["d.catalogo = %s", "d.ativo = %s", "d.servidor = %s", "d.instalado = %s"]
    parametros = [catalogo, filtro_ativo, filtro_servidor, filtro_instalado]

    where_sql = " AND ".join(condicoes)

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        f"SELECT d.id, d.cliente, d.apelido, d.observacao, d.usuario, d.ativo, d.servidor, d.catalogo, "
        f"d.sistema, d.memoria, d.processador, d.computador, "
        f"d.ultima_vez_online, d.inclusao, d.atualizado, "
        # item 30: versao do ERP (licencas.id_mrdesk = devices.id, no maximo 1 por device)
        f"l.versao AS versao_erp, "
        # tempo sem sinal calculado DENTRO do banco (mesmo relogio que gravou
        # ultima_vez_online) - nao depende do relogio/fuso do Python
        f"EXTRACT(EPOCH FROM (NOW() - d.ultima_vez_online)) AS segundos_sem_sinal, "
        f"EXTRACT(EPOCH FROM (NOW() - d.ultima_atividade)) AS segundos_sem_uso "
        f"FROM devices d LEFT JOIN licencas l ON l.id_mrdesk = d.id "
        f"WHERE {where_sql} ORDER BY d.cliente, d.apelido",
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
    cur.execute("SELECT id, cliente FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        link = f"{ESQUEMA_CONEXAO}://{modo}/{row['id']}"
        # Item 27: o MrDeskPro (patch 12) usa o nome do cliente como nome da aba
        cliente = (row["cliente"] or "").strip()
        if cliente:
            from urllib.parse import quote
            link += "?cliente=" + quote(cliente, safe="")
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
        "SELECT inicio, fim, nome, origem, tipo, ip, permissao, autenticacao "
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
# LIBERAR NOVA MAQUINA (item 9) - so admin. Apaga devices.uuid; o proximo
# contato do MrDesk (heartbeat em segundos) grava o uuid novo.
# ------------------------------------------------------------
@app.route("/api/devices/<device_id>/liberar-maquina", methods=["POST"])
@require_auth
@require_admin
def liberar_maquina(device_id):
    conn = get_db()
    cur = conn.cursor()
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
        cur.execute(
            "INSERT INTO devices (id, cliente, apelido, usuario, catalogo, ultima_vez_online, uuid) "
            "VALUES (%s, %s, %s, %s, %s, NOW(), %s) ON CONFLICT (id) DO NOTHING",
            (device_id, "A definir", device_id, "sistema", 1, uuid_env)
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
    cur.execute("SELECT id, apelido FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()

    if row:
        # Ja existe: nao mexe em apelido/cliente (o tecnico pode ja
        # ter personalizado), so atualiza a observacao com o SO e
        # marca que esta vivo agora. instalado so e sobrescrito quando o
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
            "INSERT INTO devices (id, cliente, apelido, usuario, catalogo, ultima_vez_online, instalado, "
            "sistema, memoria, processador, computador, uuid) "
            "VALUES (%s, %s, %s, %s, %s, NOW(), COALESCE(%s, 'S'), %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
            (device_id, "A definir", hostname, "sistema", 1, instalado, sistema, memoria, processador, computador,
             uuid_env)
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
    cur.execute(
        "SELECT t.dispositivo FROM tecnicos_autorizados t JOIN usuarios u ON u.usuario = t.usuario "
        "WHERE t.ativo = 'S' AND u.ativo = 'S'"
    )
    ids = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    lista = sorted(hashlib.sha256(f"{cliente}:{tec}".encode()).hexdigest() for tec in ids)
    return jsonify({"lista": lista, "validade_dias": VALIDADE_LISTA_DIAS})


# ------------------------------------------------------------
# LOGIN E CATALOGO DE ENDERECOS DO MRDESKPRO (item 24)
# ------------------------------------------------------------
# O MrDeskPro (login liberado so nele) usa o "catalogo de enderecos" nativo do
# RustDesk no modo simples ("legacy"): /api/login, /api/currentUser,
# /api/logout e GET /api/ab. /api/ab/personal NAO existe (404) - e assim que o
# MrDeskPro sabe que deve usar o modo simples.
# - Login com usuario/senha do painel, usuario ativo, e SO a partir de um
#   MrDeskPro cadastrado em Tecnicos autorizados pra esse mesmo usuario.
# - Sessao vale 30 dias (depois, entrar de novo). Usuario ou MrDeskPro
#   desativado -> a sessao cai na proxima conferencia.
# - Catalogo: devices ativo = S, instalado = S e servidor = S; somente leitura;
#   sem senha/hash (o RustDesk permite guardar atalho de senha no catalogo).
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


def _usuario_pro_valido(cur, usuario_id, dispositivo):
    # usuario ativo + esse MrDeskPro ativo e dele. Devolve (nome, admin, email) ou None.
    cur.execute(
        "SELECT u.nome, u.admin, u.email FROM usuarios u "
        "JOIN tecnicos_autorizados t ON t.usuario = u.usuario "
        "WHERE u.usuario = %s AND u.ativo = 'S' AND t.dispositivo = %s AND t.ativo = 'S'",
        (usuario_id, dispositivo)
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
        dados = serializer_pro.loads(token, max_age=VALIDADE_SESSAO_PRO)
    except (SignatureExpired, BadSignature):
        return None
    conn = get_db()
    cur = conn.cursor()
    linha = _usuario_pro_valido(cur, dados.get("u"), dados.get("d"))
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
    nome = (data.get("username") or "").strip()
    senha = data.get("password") or ""
    dispositivo = _normalizar_id(data.get("id"))
    if not nome or not senha or not dispositivo:
        return jsonify({"error": "Informe usuário e senha."}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT usuario, nome, senha, admin, email FROM usuarios WHERE nome = %s AND ativo = 'S'", (nome,))
    user = cur.fetchone()
    ok_senha = bool(user) and bcrypt.checkpw(senha.encode(), user["senha"].encode())
    autorizado = None
    if ok_senha:
        cur2 = conn.cursor()
        autorizado = _usuario_pro_valido(cur2, user["usuario"], dispositivo)
        cur2.close()
    cur.close()
    conn.close()

    if not ok_senha:
        return jsonify({"error": "Usuário ou senha inválidos."}), 401
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


@app.route("/api/ab", methods=["GET"])
def catalogo_pro():
    import json as _json
    if not _sessao_pro():
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT d.id, d.cliente, d.apelido, d.sistema, c.nome AS catalogo_nome "
        "FROM devices d LEFT JOIN catalogos c ON c.catalogo = d.catalogo "
        "WHERE d.ativo = 'S' AND d.instalado = 'S' AND d.servidor = 'S' "
        "ORDER BY d.cliente, d.apelido"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    peers = []
    tags = []
    for r in rows:
        tag = (r["catalogo_nome"] or "").strip()
        if tag and tag not in tags:
            tags.append(tag)
        peers.append({
            "id": r["id"],
            "username": r["cliente"] or "",   # 2a linha do card, a esquerda
            "hostname": r["apelido"] or "",   # 2a linha do card, a direita
            "alias": "",
            "platform": "Windows" if (r["sistema"] or "").lower().startswith("windows") else "",
            "tags": [tag] if tag else [],
        })
    dados = {"tags": tags, "peers": peers, "tag_colors": "{}"}
    return jsonify({"data": _json.dumps(dados, ensure_ascii=False)})


@app.route("/api/ab", methods=["POST"])
def catalogo_pro_somente_leitura():
    return jsonify({"error": "A lista do MrDeskPro vem do painel e não pode ser alterada aqui."}), 403


# Aba "Grupo" do MrDeskPro: depois do login ele pede grupos de dispositivos,
# usuarios e dispositivos acessiveis (recurso do servidor Pro do RustDesk).
# Sem estas rotas o MrDeskPro mostrava "Nao foi possivel atualizar o grupo:
# HTTP 404". Decisao do Celso (01/10): os nossos catalogos (tabela catalogos)
# aparecem como grupos de dispositivos; os dispositivos sao os mesmos do
# catalogo de enderecos (ativos, instalados e servidores). Usuarios: vazio.
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
    if not _sessao_pro():
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT nome FROM catalogos ORDER BY nome")
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
    if not _sessao_pro():
        return jsonify({"error": "Sessão expirada ou não autorizada."}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT d.id, d.cliente, d.apelido, d.sistema, c.nome AS catalogo_nome "
        "FROM devices d LEFT JOIN catalogos c ON c.catalogo = d.catalogo "
        "WHERE d.ativo = 'S' AND d.instalado = 'S' AND d.servidor = 'S' "
        "ORDER BY d.cliente, d.apelido"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    itens = [{
        "id": r["id"],
        # card: cliente a esquerda (username) e apelido a direita (device_name)
        "info": {"username": r["cliente"] or "", "device_name": r["apelido"] or "",
                 "os": r["sistema"] or ""},
        "status": 1,
        "user": "",
        "user_name": "",
        "device_group_name": (r["catalogo_nome"] or "").strip(),
        "note": "",
    } for r in rows]
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
    permissao = COALESCE(%(permissao)s, auditoria.permissao)
"""

_AUDIT_INSERT = """
    INSERT INTO auditoria (dispositivo, acesso, sessao, ip, origem, nome, tipo, uuid, inicio, fim, permissao,
                           autenticacao)
    VALUES (%(dispositivo)s, {acesso}, %(sessao)s, %(ip)s, %(origem)s, %(nome)s, %(tipo)s, %(uuid)s,
            NOW(), CASE WHEN %(fecha)s THEN NOW() ELSE NULL END, COALESCE(%(permissao)s, 'P'),
            %(autenticacao)s)
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
    }

    conn = get_db()
    cur = conn.cursor()
    try:
        # Item 9: so grava aviso da maquina registrada pra esse ID.
        if not _maquina_confere(cur, p["dispositivo"], p["uuid"], "auditoria"):
            conn.commit()
            return ("", 200)
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
