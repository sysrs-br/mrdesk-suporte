-- Item 30: versao do ERP na lista de dispositivos.
-- licencas.id_mrdesk liga a licenca ao dispositivo (devices.id); preenchido a
-- mao no banco. No maximo uma licenca por dispositivo.
-- Rodar como postgres:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -f /opt/mrdesk-suporte/licenca-banco.sql

BEGIN;
SET ROLE mrdesk;
ALTER TABLE licencas ADD COLUMN id_mrdesk VARCHAR(20);
ALTER TABLE licencas ADD CONSTRAINT fk_licencas_device
    FOREIGN KEY (id_mrdesk) REFERENCES devices (id);
ALTER TABLE licencas ADD CONSTRAINT uk_licencas_id_mrdesk UNIQUE (id_mrdesk);
COMMENT ON COLUMN licencas.id_mrdesk IS
  'ID do dispositivo no MrDesk (devices.id) onde roda esta licenca. Preenchido '
  'a mao. Usado para mostrar a versao do ERP na lista de dispositivos do painel. '
  'No maximo uma licenca por dispositivo.';
COMMIT;
