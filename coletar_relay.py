# ============================================================
#  MrDesk Suporte - Coletor de sessoes do relay (hbbr)
#  Sysrs Tecnologia da Informacao
# ============================================================
#
# Roda a cada 5 minutos pelo timer do systemd (mrdesk-relay.timer).
#
# Le SO as linhas novas do log do hbbr desde a ultima execucao (o journalctl
# guarda a posicao no arquivo CURSOR_FILE), pega cada sessao real que passou
# pelo relay e grava na tabela relay_sessoes. Assim o painel so precisa
# contar linhas no banco (instantaneo), e o historico nao se perde quando o
# sistema apaga logs antigos.
#
# O hbbr escreve duas linhas por sessao, com o mesmo codigo:
#   New relay request <codigo> from [...]           <- primeiro lado chegou
#   Relayrequest <codigo> from [...] got paired     <- segundo lado chegou e
#                                                      os dois foram ligados
# Contamos SO as "got paired" (sessoes que realmente passaram pelo relay) E
# com codigo no formato UUID (o que o MrDesk usa). Robos que varrem a internet
# as vezes chegam a "got paired" (mandam 2 pedidos com o mesmo codigo), mas
# com codigos em outro formato; desde que o hbbr passou a exigir a chave
# (28/09), eles nem chegam la.

import json
import os
import re
import subprocess
import sys
from datetime import datetime

import psycopg2

import config

CURSOR_FILE = "/var/lib/mrdesk-relay/relay.cursor"  # pasta criada pelo systemd (StateDirectory)

PADRAO = re.compile(
    r"Relayrequest "
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r" from \[?(?:::ffff:)?([0-9a-fA-F:.]+?)\]?:\d+ got paired"
)

SQL_TABELA = """
CREATE TABLE IF NOT EXISTS relay_sessoes (
    uuid   TEXT PRIMARY KEY,
    inicio TIMESTAMP NOT NULL,
    ip     TEXT
);
CREATE INDEX IF NOT EXISTS relay_sessoes_inicio_idx ON relay_sessoes (inicio);
"""


def ler_linhas_novas():
    saida = subprocess.run(
        ["journalctl", "-u", "rustdesk-hbbr", "--cursor-file=" + CURSOR_FILE,
         "-o", "json", "--no-pager", "-q"],
        capture_output=True, text=True, timeout=120,
    )
    if saida.returncode != 0:
        raise RuntimeError("journalctl falhou: " + saida.stderr.strip())
    for linha in saida.stdout.splitlines():
        try:
            yield json.loads(linha)
        except ValueError:
            continue


def extrair_sessoes(entradas):
    sessoes = {}
    for e in entradas:
        mensagem = e.get("MESSAGE")
        if not isinstance(mensagem, str):
            continue
        m = PADRAO.search(mensagem)
        if not m:
            continue
        uuid = m.group(1).lower()
        if uuid in sessoes:
            continue
        # __REALTIME_TIMESTAMP vem em microssegundos (UTC); gravamos no
        # horario local da VM, igual as outras tabelas (NOW()).
        inicio = datetime.fromtimestamp(int(e["__REALTIME_TIMESTAMP"]) / 1_000_000)
        sessoes[uuid] = (uuid, inicio, m.group(2))
    return list(sessoes.values())


def main():
    # Guarda a posicao atual: o journalctl avanca o cursor ao ler, entao se a
    # gravacao no banco falhar a gente volta a posicao e tenta de novo na
    # proxima execucao (sem perder sessoes).
    cursor_anterior = None
    if os.path.exists(CURSOR_FILE):
        with open(CURSOR_FILE) as f:
            cursor_anterior = f.read()

    try:
        sessoes = extrair_sessoes(ler_linhas_novas())

        conn = psycopg2.connect(
            host=config.DB_HOST, dbname=config.DB_NAME,
            user=config.DB_USER, password=config.DB_PASSWORD,
        )
        try:
            cur = conn.cursor()
            cur.execute(SQL_TABELA)
            for s in sessoes:
                cur.execute(
                    "INSERT INTO relay_sessoes (uuid, inicio, ip) VALUES (%s, %s, %s) "
                    "ON CONFLICT (uuid) DO NOTHING",
                    s,
                )
            conn.commit()
            cur.close()
        finally:
            conn.close()
    except Exception:
        if cursor_anterior is None:
            if os.path.exists(CURSOR_FILE):
                os.remove(CURSOR_FILE)
        else:
            with open(CURSOR_FILE, "w") as f:
                f.write(cursor_anterior)
        raise

    print(f"{len(sessoes)} sessao(oes) de relay nova(s) processada(s)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERRO: {e}", file=sys.stderr)
        sys.exit(1)
