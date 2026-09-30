-- MrDesk - Controle de acesso 6A (aprovado pelo Celso em 29/09/2026)
BEGIN;
SET ROLE mrdesk;

ALTER TABLE catalogos ADD COLUMN senha_geral VARCHAR(1) DEFAULT 'N';

CREATE TABLE tecnicos_autorizados (
    dispositivo  VARCHAR(20) NOT NULL,
    usuario      INTEGER NOT NULL,
    descricao    VARCHAR(100),
    ativo        VARCHAR(1) DEFAULT 'S',
    inclusao     TIMESTAMP DEFAULT NOW(),
    alterado     TIMESTAMP DEFAULT NOW(),
    CONSTRAINT pk_tecnicos_autorizados PRIMARY KEY (dispositivo),
    CONSTRAINT fk_tecnico_device  FOREIGN KEY (dispositivo) REFERENCES devices (id),
    CONSTRAINT fk_tecnico_usuario FOREIGN KEY (usuario) REFERENCES usuarios (usuario)
);

ALTER TABLE auditoria ALTER COLUMN dispositivo TYPE VARCHAR(20);
ALTER TABLE auditoria ALTER COLUMN origem TYPE VARCHAR(20);
ALTER TABLE auditoria ADD COLUMN permissao VARCHAR(1) NOT NULL DEFAULT 'P';
ALTER TABLE auditoria ADD CONSTRAINT fk_auditoria_device
    FOREIGN KEY (dispositivo) REFERENCES devices (id);

COMMIT;
