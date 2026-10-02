-- Item 33: como o acesso foi autorizado (o MrDesk ja manda no aviso de login).
-- Rodar como postgres:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -f /opt/mrdesk-suporte/autenticacao-banco.sql

BEGIN;
SET ROLE mrdesk;
ALTER TABLE auditoria ADD COLUMN autenticacao SMALLINT;
COMMENT ON COLUMN auditoria.autenticacao IS
  'Como o acesso foi autorizado (enviado pelo MrDesk): 1 = aceite na tela, '
  '2 = senha temporaria, 3 = senha permanente, 4 = troca de lado. Vazio = nao informado.';
COMMIT;
