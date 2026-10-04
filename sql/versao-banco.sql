-- Versao do MrDesk instalada em cada dispositivo (04/10/2026).
-- Rodar como postgres:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -f /opt/mrdesk-suporte/versao-banco.sql

BEGIN;
SET ROLE mrdesk;
ALTER TABLE devices ADD COLUMN versao VARCHAR(15);
COMMENT ON COLUMN devices.versao IS
  'Versao do MrDesk (ou MrDeskPro) instalada, informada pelo proprio programa em '
  'cada heartbeat e no sysinfo. Nulo = a maquina ainda nao deu sinal depois que a '
  'coluna foi criada. O painel marca como desatualizada a maquina com versao '
  'anterior a dos exes publicados em updates, e tambem a que esta sem versao.';
COMMIT;
