-- MrDesk - Item 16: hora da ultima atividade (teclado/mouse) no computador do cliente
-- Aprovado pelo Celso em 30/09/2026
BEGIN;
SET ROLE mrdesk;
ALTER TABLE devices ADD COLUMN ultima_atividade TIMESTAMP;
COMMIT;
