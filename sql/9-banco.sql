-- Item 9: maquina registrada de cada dispositivo (contra auditoria falsa).
-- Rodar como postgres:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -f /opt/mrdesk-suporte/9-banco.sql

BEGIN;
SET ROLE mrdesk;
ALTER TABLE devices ADD COLUMN uuid VARCHAR(64);
COMMENT ON COLUMN devices.uuid IS
  'Codigo da maquina (uuid que o MrDesk manda; vem da instalacao do Windows). '
  'Gravado no primeiro contato. Heartbeat, sysinfo e auditoria com uuid diferente '
  'sao recusados (e vao pro log), para ninguem gerar auditoria falsa nem alterar '
  'o dispositivo sem conhecer esse codigo. Muda quando o Windows e reinstalado '
  '(o ID continua o mesmo): o computador fica off-line no painel e nao gera '
  'auditoria ate o admin usar "Liberar nova maquina", que apaga este campo; '
  'o proximo contato grava o novo.';
COMMIT;
