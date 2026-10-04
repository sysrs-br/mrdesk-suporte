-- Senha permanente por tecnico (04/10/2026).
-- O numero da senha (1 a 5) deixa de ser da empresa e passa a ser de cada usuario:
--   admin de empresa : definido pelo superadmin (a 1 e reservada; em principio, Sysrs)
--   tecnico          : definido pelo admin, do numero do admin ate 5
--   superadmin       : nao tem
-- A coluna usuarios.acesso passa a se chamar senha_permanente.
-- Rodar como postgres, JUNTO com o app.py novo (o antigo usa usuarios.acesso):
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -v ON_ERROR_STOP=1 -f /opt/mrdesk-suporte/senha-permanente-banco.sql

BEGIN;
SET ROLE mrdesk;

ALTER TABLE usuarios RENAME COLUMN acesso TO senha_permanente;
ALTER TABLE usuarios RENAME CONSTRAINT ck_usuarios_acesso TO ck_usuarios_senha_permanente;

-- Mesmo trigger (tg_biu_usuarios), com as regras novas da senha permanente
CREATE OR REPLACE FUNCTION tg_biu_usuarios() RETURNS trigger AS $$
DECLARE
    m usuarios%ROWTYPE;
BEGIN
    NEW.email := LOWER(TRIM(NEW.email));
    IF NEW.admin NOT IN ('S', 'N') OR NEW.ativo NOT IN ('S', 'N') THEN
        RAISE EXCEPTION 'usuarios: admin e ativo aceitam so S ou N';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.master IS NULL AND NEW.master IS NOT NULL THEN
            RAISE EXCEPTION 'usuarios: o superadmin nao pode ter master';
        END IF;
        IF (NEW.admin IS DISTINCT FROM OLD.admin OR NEW.master IS DISTINCT FROM OLD.master)
           AND EXISTS (SELECT 1 FROM usuarios WHERE master = OLD.usuario) THEN
            RAISE EXCEPTION 'usuarios: nao se altera admin nem master de usuario que tem subordinados';
        END IF;
    END IF;

    IF NEW.master IS NULL THEN
        -- superadmin (o indice uk_usuarios_superadmin garante que e um so)
        IF NEW.admin <> 'S' THEN
            RAISE EXCEPTION 'usuarios: o superadmin tem de ser admin';
        END IF;
        IF NEW.ativo <> 'S' THEN
            RAISE EXCEPTION 'usuarios: o superadmin nao pode ser desativado';
        END IF;
        IF NEW.senha_permanente IS NOT NULL OR NEW.empresa IS NOT NULL THEN
            RAISE EXCEPTION 'usuarios: o superadmin nao tem senha permanente nem empresa';
        END IF;
    ELSE
        IF NEW.master = NEW.usuario THEN
            RAISE EXCEPTION 'usuarios: o usuario nao pode ser master dele mesmo';
        END IF;
        SELECT * INTO m FROM usuarios WHERE usuario = NEW.master;
        IF NEW.admin = 'S' THEN
            -- admin de empresa
            IF m.master IS NOT NULL THEN
                RAISE EXCEPTION 'usuarios: o master de um admin de empresa tem de ser o superadmin';
            END IF;
            IF NEW.senha_permanente IS NULL OR COALESCE(TRIM(NEW.empresa), '') = '' THEN
                RAISE EXCEPTION 'usuarios: admin de empresa precisa de empresa e do numero da senha permanente';
            END IF;
            -- os tecnicos dele vao do numero dele ate 5
            IF EXISTS (SELECT 1 FROM usuarios WHERE master = NEW.usuario
                          AND senha_permanente < NEW.senha_permanente) THEN
                RAISE EXCEPTION 'usuarios: ha tecnico desta empresa com senha permanente menor que a do admin';
            END IF;
        ELSE
            -- tecnico
            IF m.admin <> 'S' OR m.master IS NULL THEN
                RAISE EXCEPTION 'usuarios: o master de um tecnico tem de ser um admin de empresa';
            END IF;
            IF NEW.empresa IS NOT NULL THEN
                RAISE EXCEPTION 'usuarios: empresa e so dos admins de empresa';
            END IF;
            IF NEW.senha_permanente IS NULL OR NEW.senha_permanente < m.senha_permanente THEN
                RAISE EXCEPTION 'usuarios: a senha permanente do tecnico vai do numero do admin da empresa ate 5';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Tecnicos atuais recebem o numero do admin da empresa deles (Sysrs = 1)
UPDATE usuarios t SET senha_permanente = a.senha_permanente
  FROM usuarios a
 WHERE t.admin = 'N' AND a.usuario = t.master;

COMMENT ON COLUMN usuarios.senha_permanente IS
  'Numero da senha permanente (1 a 5) que este usuario usa no MrDesk. '
  'Admin de empresa: definido pelo superadmin (1 = reservada, em principio da Sysrs). '
  'Tecnico: definido pelo admin, do numero do admin ate 5. Nulo no superadmin.';

COMMIT;
