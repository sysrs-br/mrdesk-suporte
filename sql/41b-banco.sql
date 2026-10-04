-- Item 41, entrega 2: contas (catalogos, dispositivos e auditoria por conta).
-- Conta = usuario admin da empresa. Tudo o que existe hoje fica na conta 2 (Sysrs).
--   catalogos       : passam a ser da conta; chave (conta, catalogo); sai senha_geral
--   devices_contas  : ficha do dispositivo em cada conta (cliente, apelido, catalogo...)
--   devices         : ficam so os dados da maquina
--   auditoria.conta : conta do tecnico, gravada na hora do acesso
--   tecnicos_autorizados.catalogo_lido : quando aquele MrDeskPro baixou o catalogo
-- Rodar como postgres, JUNTO com o app.py novo (o antigo le devices.cliente etc.):
--   sudo -u postgres /usr/local/pgsql/bin/psql -d mrdesk -v ON_ERROR_STOP=1 -f /opt/mrdesk-suporte/41b-banco.sql

BEGIN;
SET ROLE mrdesk;

-- Confere se a conta 2 e o admin da Sysrs (entrega 1 aplicada); senao para sem mexer em nada.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM usuarios WHERE usuario = 2 AND admin = 'S' AND master IS NOT NULL) THEN
        RAISE EXCEPTION 'O usuario 2 nao e o admin de empresa da Sysrs. Nada foi alterado.';
    END IF;
END $$;

-- MrDeskPro que estiver cadastrado no superadmin passa pro admin da Sysrs
-- (o superadmin nao faz acesso remoto nem tem conta).
UPDATE tecnicos_autorizados SET usuario = 2
 WHERE usuario IN (SELECT usuario FROM usuarios WHERE master IS NULL);

-- Catalogos por conta
ALTER TABLE devices DROP CONSTRAINT fk_device_catalogo;
ALTER TABLE catalogos ALTER COLUMN catalogo TYPE INTEGER;
ALTER TABLE catalogos ADD COLUMN conta INTEGER;
UPDATE catalogos SET conta = 2;
ALTER TABLE catalogos ALTER COLUMN conta SET NOT NULL;
ALTER TABLE catalogos ADD CONSTRAINT fk_catalogos_conta
    FOREIGN KEY (conta) REFERENCES usuarios (usuario);
ALTER TABLE catalogos DROP CONSTRAINT pk_catalogos;
ALTER TABLE catalogos ADD CONSTRAINT pk_catalogos PRIMARY KEY (conta, catalogo);
ALTER TABLE catalogos ADD CONSTRAINT uk_catalogos_nome UNIQUE (conta, nome);
ALTER TABLE catalogos DROP COLUMN senha_geral;
COMMENT ON COLUMN catalogos.conta IS
  'Conta dona do catalogo = usuario admin da empresa. A numeracao (catalogo) recomeca em cada conta.';

-- Toda conta tem o catalogo "Novos" (numero 0, fixo): e onde a maquina entra no
-- primeiro acesso de um tecnico. Nao pode ser renomeado; o admin move a
-- maquina dali pro catalogo certo.
INSERT INTO catalogos (conta, catalogo, nome)
SELECT u.usuario, 0, 'Novos' FROM usuarios u
 WHERE u.admin = 'S' AND u.master IS NOT NULL;
COMMENT ON COLUMN catalogos.catalogo IS
  'Numero do catalogo dentro da conta. 0 = "Novos" (fixo, criado com a conta): '
  'recebe as maquinas no primeiro acesso.';

-- Ficha do dispositivo em cada conta
CREATE TABLE devices_contas (
    dispositivo  VARCHAR(20)  NOT NULL,
    conta        INTEGER      NOT NULL,
    cliente      VARCHAR(100),
    apelido      VARCHAR(100) NOT NULL,
    observacao   TEXT,
    usuario      VARCHAR(100),
    catalogo     INTEGER      NOT NULL,
    ativo        CHAR(1)      NOT NULL DEFAULT 'S',
    servidor     CHAR(1)      NOT NULL DEFAULT 'N',
    inclusao     TIMESTAMP DEFAULT NOW(),
    atualizado   TIMESTAMP DEFAULT NOW(),
    CONSTRAINT pk_devices_contas PRIMARY KEY (dispositivo, conta),
    CONSTRAINT fk_devices_contas_device   FOREIGN KEY (dispositivo) REFERENCES devices (id),
    CONSTRAINT fk_devices_contas_conta    FOREIGN KEY (conta) REFERENCES usuarios (usuario),
    CONSTRAINT fk_devices_contas_catalogo FOREIGN KEY (conta, catalogo) REFERENCES catalogos (conta, catalogo)
);
COMMENT ON TABLE devices_contas IS
  'Ligacao dispositivo x conta, com a ficha que cada conta tem do dispositivo. '
  'Nasce no primeiro acesso remoto que der certo de um tecnico da conta, no catalogo Novos (0). '
  'Maquina atendida por duas contas = duas linhas. Remover da conta = apagar a linha.';
COMMENT ON COLUMN devices_contas.conta IS 'Usuario admin da empresa.';
COMMENT ON COLUMN devices_contas.cliente IS
  'Nome do cliente. Nulo = ainda nao informado: as telas mostram so o apelido.';
COMMENT ON COLUMN devices_contas.usuario IS 'Quem editou a ficha por ultimo.';

-- Migracao: todo dispositivo de hoje vai pra conta da Sysrs, com a ficha atual.
-- Cliente "A definir" vira nulo.
INSERT INTO devices_contas (dispositivo, conta, cliente, apelido, observacao, usuario, catalogo,
                            ativo, servidor, inclusao, atualizado)
SELECT d.id, 2, NULLIF(TRIM(d.cliente), 'A definir'), d.apelido, d.observacao, d.usuario,
       COALESCE(d.catalogo, (SELECT MIN(catalogo) FROM catalogos WHERE conta = 2))::INTEGER,
       d.ativo, d.servidor, d.inclusao, d.atualizado
  FROM devices d;

ALTER TABLE devices DROP COLUMN cliente;
ALTER TABLE devices DROP COLUMN apelido;
ALTER TABLE devices DROP COLUMN observacao;
ALTER TABLE devices DROP COLUMN usuario;
ALTER TABLE devices DROP COLUMN catalogo;
ALTER TABLE devices DROP COLUMN ativo;
ALTER TABLE devices DROP COLUMN servidor;

-- Auditoria: conta do tecnico, gravada na hora do acesso
ALTER TABLE auditoria ADD COLUMN conta INTEGER;
ALTER TABLE auditoria ADD CONSTRAINT fk_auditoria_conta
    FOREIGN KEY (conta) REFERENCES usuarios (usuario);
UPDATE auditoria SET conta = 2;
COMMENT ON COLUMN auditoria.conta IS
  'Conta (usuario admin da empresa) do tecnico que acessou, gravada no login do acesso. '
  'Nulo = acesso que nao chegou ao login ou veio de quem nao e tecnico de nenhuma conta.';

-- Quando cada MrDeskPro baixou o catalogo pela ultima vez
ALTER TABLE tecnicos_autorizados ADD COLUMN catalogo_lido TIMESTAMP;
COMMENT ON COLUMN tecnicos_autorizados.catalogo_lido IS
  'Momento em que este MrDeskPro baixou o catalogo pela ultima vez. O MrDeskPro reenvia '
  'o catalogo inteiro sozinho; alteracao vinda dele so vale pra ficha que nao mudou '
  'depois dessa leitura (senao uma copia velha desfaria o que o admin fez no painel).';

COMMIT;
