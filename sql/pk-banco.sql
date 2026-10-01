-- Renomeia as chaves primarias para o padrao pk_<tabela>.
-- catalogos e tecnicos_autorizados ja estao no padrao.
-- auditoria fica para o item 13 (a PK sera trocada e ja nasce pk_auditoria).
-- Rodar como postgres:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -f /opt/mrdesk-suporte/pk-banco.sql

BEGIN;
ALTER TABLE devices       RENAME CONSTRAINT devices_pkey       TO pk_devices;
ALTER TABLE licencas      RENAME CONSTRAINT licencas_pkey      TO pk_licencas;
ALTER TABLE versoes       RENAME CONSTRAINT versoes_pkey       TO pk_versoes;
ALTER TABLE usuarios      RENAME CONSTRAINT usuarios_pkey      TO pk_usuarios;
ALTER TABLE relay_sessoes RENAME CONSTRAINT relay_sessoes_pkey TO pk_relay_sessoes;
COMMIT;
