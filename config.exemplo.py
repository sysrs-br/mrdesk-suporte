# ============================================================
#  MrDesk Suporte - Configuracao (MODELO)
# ============================================================
# Copie este arquivo para "config.py" na VM e preencha os valores.
# O config.py real tem senhas e NAO vai para o repositorio.

# Banco PostgreSQL do backend
DB_HOST = "localhost"
DB_NAME = "..."
DB_USER = "..."
DB_PASSWORD = "..."

# Chave usada para criptografia de dados
ENCRYPTION_KEY = "..."

# Servidor de ID do RustDesk (hbbs)
RUSTDESK_ID_SERVER = "mrdesk.sysrs.com.br"

# Chave secreta dos tokens de login do painel
APP_SECRET_KEY = "..."

# Endereco do painel (vai nos links de senha enviados por e-mail)
PAINEL_URL = "https://mrdesk.sysrs.com.br"

# Envio de e-mail (link para criar/redefinir senha e aviso de senha alterada)
SMTP_HOST = "..."                # ex.: smtp.seudominio.com.br
SMTP_PORT = 587
SMTP_SEGURANCA = "starttls"      # "starttls" (porta 587) ou "ssl" (porta 465)
SMTP_USUARIO = "..."             # conta que envia
SMTP_SENHA = "..."
SMTP_REMETENTE = "MrDesk <naoresponda@sysrs.com.br>"
