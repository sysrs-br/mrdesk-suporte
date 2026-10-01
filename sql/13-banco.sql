-- Item 13: chave natural da auditoria = (dispositivo, acesso).
-- acesso (BIGINT) = segundo do inicio do servico do MrDesk * 1.000.000 + conn_id.
-- Saem a sequencia (serial, nenhuma FK aponta pra ela) e a conexao
-- (fica dentro do acesso: acesso % 1000000).
-- Linhas antigas: acesso = segundo do inicio * 1.000.000 + conexao
-- (sem colisao: (dispositivo, conexao) ja era unico e conexao < 1.000.000).
-- Rodar como postgres, JUNTO com o app.py novo (o antigo grava em conexao):
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -f /opt/mrdesk-suporte/13-banco.sql

BEGIN;
SET ROLE mrdesk;
ALTER TABLE auditoria ADD COLUMN acesso BIGINT;
UPDATE auditoria
   SET acesso = TRUNC(EXTRACT(EPOCH FROM inicio))::BIGINT * 1000000 + conexao;
ALTER TABLE auditoria ALTER COLUMN acesso SET NOT NULL;
ALTER TABLE auditoria DROP CONSTRAINT auditoria_pkey;
ALTER TABLE auditoria DROP CONSTRAINT auditoria_dispositivo_conexao_key;
ALTER TABLE auditoria ADD CONSTRAINT pk_auditoria PRIMARY KEY (dispositivo, acesso);
ALTER TABLE auditoria DROP COLUMN sequencia;
ALTER TABLE auditoria DROP COLUMN conexao;
COMMIT;
