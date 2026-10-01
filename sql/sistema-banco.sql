-- MrDesk - colunas de sistema do device (aplicado na VM em 01/10/2026)
BEGIN;
ALTER TABLE devices ADD COLUMN sistema VARCHAR(150);
ALTER TABLE devices ADD COLUMN memoria VARCHAR(20);
ALTER TABLE devices ADD COLUMN processador VARCHAR(150);
ALTER TABLE devices ADD COLUMN computador VARCHAR(100);
COMMIT;
