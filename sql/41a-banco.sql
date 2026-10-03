-- Item 41, entrega 1: usuarios (master, tres tipos, login por e-mail, link de senha, log).
-- Conta = o proprio usuario admin da empresa (nao existe tabela de contas).
--   superadmin        : master nulo, admin = 'S' (um e so um)
--   admin de empresa  : admin = 'S', master = superadmin
--   tecnico           : admin = 'N', master = admin da empresa
-- Rodar como postgres, JUNTO com o app.py novo (o antigo usa excluir_device):
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -v ON_ERROR_STOP=1 -f /opt/mrdesk-suporte/41a-banco.sql

BEGIN;
SET ROLE mrdesk;

-- Confere se os usuarios sao os que a migracao espera (senao, para sem mexer em nada).
DO $$
BEGIN
    IF (SELECT COUNT(*) FROM usuarios) <> 4
       OR NOT EXISTS (SELECT 1 FROM usuarios WHERE usuario = 1 AND nome = 'admin' AND admin = 'S')
       OR NOT EXISTS (SELECT 1 FROM usuarios WHERE usuario = 2 AND nome = 'Celso')
       OR NOT EXISTS (SELECT 1 FROM usuarios WHERE usuario = 3 AND nome = 'Fernando')
       OR NOT EXISTS (SELECT 1 FROM usuarios WHERE usuario = 4 AND nome = 'Suporte01') THEN
        RAISE EXCEPTION 'Os usuarios nao sao os esperados pela migracao (1 admin, 2 Celso, 3 Fernando, 4 Suporte01). Nada foi alterado.';
    END IF;
END $$;

-- Colunas novas
ALTER TABLE usuarios ADD COLUMN master INTEGER;
ALTER TABLE usuarios ADD CONSTRAINT fk_usuarios_master
    FOREIGN KEY (master) REFERENCES usuarios (usuario);
ALTER TABLE usuarios ADD COLUMN acesso SMALLINT;
ALTER TABLE usuarios ADD CONSTRAINT ck_usuarios_acesso CHECK (acesso BETWEEN 1 AND 5);
ALTER TABLE usuarios ADD COLUMN empresa VARCHAR(100);
ALTER TABLE usuarios ADD COLUMN ultimo_login TIMESTAMP;
ALTER TABLE usuarios ADD COLUMN senha_alterada TIMESTAMP;
ALTER TABLE usuarios ADD COLUMN link_senha TIMESTAMP;

COMMENT ON COLUMN usuarios.master IS
  'Usuario master deste usuario. Nulo = superadmin (um e so um). Admin de empresa: '
  'master = superadmin. Tecnico: master = admin da empresa (a "conta" e o admin).';
COMMENT ON COLUMN usuarios.acesso IS
  'Numero da senha permanente (1 a 5) que os tecnicos desta conta usam no MrDesk. '
  'So nos admins de empresa. 1 = Sysrs.';
COMMENT ON COLUMN usuarios.empresa IS 'Nome da empresa. So nos admins de empresa.';
COMMENT ON COLUMN usuarios.senha IS 'Resumo bcrypt da senha. Nulo = aguardando o usuario definir a senha pelo link.';
COMMENT ON COLUMN usuarios.senha_alterada IS
  'Momento da ultima troca de senha (segundos inteiros). Sessao do painel ou do '
  'MrDeskPro criada antes disso deixa de valer.';
COMMENT ON COLUMN usuarios.link_senha IS
  'Momento do ultimo link de senha enviado por e-mail. So o link desse momento vale; '
  'fica nulo quando o link e usado.';

-- Migracao dos usuarios atuais (as senhas continuam as mesmas)
UPDATE usuarios SET email = 'sysrs@sysrs.com.br' WHERE usuario = 1;
UPDATE usuarios SET email = LOWER(TRIM(email)),
                    admin = COALESCE(admin, 'N'),
                    ativo = COALESCE(ativo, 'S');
UPDATE usuarios SET admin = 'S', master = 1, empresa = 'Sysrs', acesso = 1 WHERE usuario = 2;
UPDATE usuarios SET master = 2 WHERE usuario IN (3, 4);

-- Restricoes
ALTER TABLE usuarios ALTER COLUMN senha DROP NOT NULL;
ALTER TABLE usuarios ALTER COLUMN email SET NOT NULL;
ALTER TABLE usuarios ADD CONSTRAINT uk_usuarios_email UNIQUE (email);
ALTER TABLE usuarios DROP CONSTRAINT usuarios_nome_key;
ALTER TABLE usuarios ALTER COLUMN admin SET NOT NULL;
ALTER TABLE usuarios ALTER COLUMN ativo SET NOT NULL;
ALTER TABLE usuarios DROP COLUMN excluir_device;
CREATE UNIQUE INDEX uk_usuarios_superadmin ON usuarios ((master IS NULL)) WHERE master IS NULL;

-- Regras dos tres tipos de usuario
CREATE FUNCTION tg_biu_usuarios() RETURNS trigger AS $$
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
        IF NEW.acesso IS NOT NULL OR NEW.empresa IS NOT NULL THEN
            RAISE EXCEPTION 'usuarios: acesso e empresa sao so dos admins de empresa';
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
            IF NEW.acesso IS NULL OR COALESCE(TRIM(NEW.empresa), '') = '' THEN
                RAISE EXCEPTION 'usuarios: admin de empresa precisa de empresa e do numero do acesso';
            END IF;
        ELSE
            -- tecnico
            IF m.admin <> 'S' OR m.master IS NULL THEN
                RAISE EXCEPTION 'usuarios: o master de um tecnico tem de ser um admin de empresa';
            END IF;
            IF NEW.acesso IS NOT NULL OR NEW.empresa IS NOT NULL THEN
                RAISE EXCEPTION 'usuarios: acesso e empresa sao so dos admins de empresa';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tg_biu_usuarios BEFORE INSERT OR UPDATE ON usuarios
    FOR EACH ROW EXECUTE FUNCTION tg_biu_usuarios();

CREATE FUNCTION tg_bd_usuarios() RETURNS trigger AS $$
BEGIN
    IF OLD.master IS NULL THEN
        RAISE EXCEPTION 'usuarios: o superadmin nao pode ser excluido';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tg_bd_usuarios BEFORE DELETE ON usuarios
    FOR EACH ROW EXECUTE FUNCTION tg_bd_usuarios();

-- Registro das acoes de cadastro
CREATE TABLE log_usuarios (
    usuario  INTEGER      NOT NULL,
    data     TIMESTAMP    NOT NULL DEFAULT clock_timestamp(),
    acao     VARCHAR(1)   NOT NULL,
    autor    INTEGER,
    detalhe  VARCHAR(200),
    ip       INET,
    CONSTRAINT pk_log_usuarios PRIMARY KEY (usuario, data),
    CONSTRAINT fk_log_usuarios_usuario FOREIGN KEY (usuario) REFERENCES usuarios (usuario),
    CONSTRAINT fk_log_usuarios_autor   FOREIGN KEY (autor)   REFERENCES usuarios (usuario)
);
COMMENT ON TABLE log_usuarios IS 'Registro das acoes de cadastro de usuarios.';
COMMENT ON COLUMN log_usuarios.usuario IS 'Quem sofreu a acao.';
COMMENT ON COLUMN log_usuarios.data IS
  'Momento da acao. O padrao e clock_timestamp() (e nao NOW()) porque duas acoes '
  'do mesmo usuario na mesma transacao teriam o mesmo NOW() e bateriam na chave.';
COMMENT ON COLUMN log_usuarios.acao IS
  'C criado, D desativado, A reativado, E e-mail trocado, L link de senha enviado, '
  'S senha definida, T dados alterados.';
COMMENT ON COLUMN log_usuarios.autor IS 'Quem fez. Nulo = o proprio usuario (pelo link ou pelo "Esqueci minha senha").';

COMMIT;
