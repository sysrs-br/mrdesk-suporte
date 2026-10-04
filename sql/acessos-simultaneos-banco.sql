-- Limite de acessos simultaneos por empresa (04/10/2026, item 42).
-- Cada admin de empresa tem o numero de maquinas que os tecnicos dela podem
-- acessar ao mesmo tempo (1 a 999), definido pelo superadmin. Controle de tela
-- e transferencia de arquivos na mesma maquina contam como um acesso.
-- Rodar como postgres, JUNTO com o app.py novo:
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -v ON_ERROR_STOP=1 -f /opt/mrdesk-suporte/acessos-simultaneos-banco.sql

BEGIN;
SET ROLE mrdesk;

ALTER TABLE usuarios ADD COLUMN acessos_simultaneos SMALLINT;
ALTER TABLE usuarios ADD CONSTRAINT ck_usuarios_acessos_simultaneos
    CHECK (acessos_simultaneos BETWEEN 1 AND 999);

-- Mesmo trigger (tg_biu_usuarios): admin de empresa precisa do limite; tecnico
-- e superadmin nao tem.
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
        IF NEW.senha_permanente IS NOT NULL OR NEW.empresa IS NOT NULL
           OR NEW.acessos_simultaneos IS NOT NULL THEN
            RAISE EXCEPTION 'usuarios: o superadmin nao tem senha permanente, empresa nem limite de acessos';
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
            IF NEW.acessos_simultaneos IS NULL THEN
                RAISE EXCEPTION 'usuarios: admin de empresa precisa do limite de acessos simultaneos';
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
            IF NEW.empresa IS NOT NULL OR NEW.acessos_simultaneos IS NOT NULL THEN
                RAISE EXCEPTION 'usuarios: empresa e limite de acessos sao so dos admins de empresa';
            END IF;
            IF NEW.senha_permanente IS NULL OR NEW.senha_permanente < m.senha_permanente THEN
                RAISE EXCEPTION 'usuarios: a senha permanente do tecnico vai do numero do admin da empresa ate 5';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Admins de empresa que ja existem comecam com 999 (o superadmin ajusta depois)
UPDATE usuarios SET acessos_simultaneos = 999 WHERE admin = 'S' AND master IS NOT NULL;

COMMENT ON COLUMN usuarios.acessos_simultaneos IS
  'Quantas maquinas os tecnicos desta empresa podem acessar ao mesmo tempo (1 a 999). '
  'So nos admins de empresa, definido pelo superadmin. Controle de tela e '
  'transferencia de arquivos na mesma maquina contam como um acesso.';

COMMIT;
