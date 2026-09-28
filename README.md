# MrDesk Suporte

Backend e painel web do MrDesk (RustDesk white-label da Sysrs Tecnologia da Informação).
Roda na VM Oracle em `/opt/mrdesk-suporte`, atrás do Nginx, em `https://mrdesk.sysrs.com.br`.

## Estrutura

| Caminho | O que é |
|---|---|
| `app.py` | Backend Flask (API do painel, heartbeat/sysinfo/auditoria dos clients, atualização automática, gráficos) |
| `coletar_relay.py` | Coletor das sessões que passam pelo relay (hbbr), roda a cada 5 min |
| `systemd/mrdesk-relay.service`, `systemd/mrdesk-relay.timer` | Agendamento do coletor (vão em `/etc/systemd/system/`) |
| `static/` | Painel web (`index.html`, `app.js`, `estilo.css`) |
| `config.exemplo.py` | Modelo do `config.py` (o real tem senhas e **não** é versionado) |
| `requirements.txt` | Pacotes Python do ambiente (`venv`) |

Fora do repositório, só na VM: `config.py`, `venv/`, `updates/` (exes de atualização, sobem via WinSCP).

## Serviços na VM

- `mrdesk-suporte.service` — gunicorn, usuário `sysrs`, `127.0.0.1:5050`.
- `mrdesk-relay.timer` → `mrdesk-relay.service` — coletor do relay.

## Aplicar alterações na VM

- `app.py` ou `coletar_relay.py`: copiar para `/opt/mrdesk-suporte/` e `sudo systemctl restart mrdesk-suporte`
  (o coletor não precisa de restart: roda a cada 5 min).
- `static/*`: copiar para `/opt/mrdesk-suporte/static/` e Ctrl+F5 no navegador.
- `systemd/*`: copiar para `/etc/systemd/system/` e `sudo systemctl daemon-reload`.
