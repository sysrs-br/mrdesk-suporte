-- Copia do catalogo que cada MrDeskPro tem (04/10/2026).
-- Serve pra o servidor saber se o tecnico alterou algo (renomear/etiqueta) ou
-- se o MrDeskPro so reenviou a lista, e pra avisar quando a lista dele esta velha.
-- Rodar como postgres, ANTES de subir o app.py novo:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -v ON_ERROR_STOP=1 -f /opt/mrdesk-suporte/versao-catalogo-local-banco.sql

BEGIN;
SET ROLE mrdesk;

ALTER TABLE tecnicos_autorizados ADD COLUMN versao_catalogo_local JSONB;
COMMENT ON COLUMN tecnicos_autorizados.versao_catalogo_local IS
  'Copia do catalogo que este MrDeskPro tem: por dispositivo, o nome e a etiqueta '
  'que o servidor mandou ou recebeu dele por ultimo. Serve pra saber se o tecnico '
  'alterou algo ou se o MrDeskPro so reenviou a lista.';

COMMIT;
